"""Cryptographic verification of npm build provenance (SLSA v1 attestations signed with Sigstore).

For each npm package version that publishes provenance:
  1. Fetch the attestation bundle from the npm registry (hardened client, cached).
  2. Verify it with sigstore-python against the Sigstore public-good trust root: the DSSE signature,
     the Fulcio certificate chain, and the Rekor transparency-log inclusion proof/timestamp.
  3. Bind identity: the signing certificate must have been issued by GitHub Actions' OIDC issuer to the
     SAME source repository and commit that the provenance statement claims.
  4. Bind the artifact: the statement's subject must be pkg:npm/<name>@<version> and its SHA-512 digest
     must equal the integrity hash in the lockfile (or, if absent, the registry's published hash).
  5. Cross-check the attested source repository with the repository the registry metadata declares.

Outcome per package: verified | invalid | repo_mismatch | absent | unsupported | unavailable.
No package code is downloaded or executed; only the attestation JSON is fetched.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from .intel import IntelContext
from .intel.http import request_json
from .models import Package

log = logging.getLogger("sentinel.provenance")

SLSA_V1 = "https://slsa.dev/provenance/v1"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
MAX_VERIFY = 60

_verifier = None
_verifier_mode = None
_vlock = threading.Lock()


def _get_verifier(offline: bool):
    """Sigstore verifier. Online mode refreshes the trust root via TUF (tuf-repo-cdn.sigstore.dev);
    offline mode (or on failure) uses the trust root embedded in / cached by sigstore-python."""
    global _verifier, _verifier_mode
    from sigstore.verify import Verifier
    with _vlock:
        want = "offline" if offline else "online"
        if _verifier is not None and (_verifier_mode == want or _verifier_mode == "online"):
            return _verifier, _verifier_mode
        if not offline:
            try:
                _verifier, _verifier_mode = Verifier.production(offline=False), "online"
                return _verifier, _verifier_mode
            except Exception as exc:  # network/TUF failure: fall back to the embedded trust root
                log.warning("sigstore trust root refresh failed (%s); using offline trust root", type(exc).__name__)
        _verifier, _verifier_mode = Verifier.production(offline=True), "offline"
        return _verifier, _verifier_mode


def _norm_repo(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url.strip(), re.I)
    return f"github.com/{m.group(1)}/{m.group(2)}".lower() if m else url.strip().lower()


def _sri_to_hex(integrity: Optional[str]) -> Optional[str]:
    if not integrity or not integrity.startswith("sha512-"):
        return None
    try:
        return base64.b64decode(integrity[7:].split()[0]).hex()
    except (ValueError, base64.binascii.Error):
        return None


def fetch_attestations(ictx: IntelContext, name: str, version: str) -> tuple[Optional[dict], str]:
    spec = quote(f"{name}@{version}", safe="@")
    if name.startswith("@"):
        spec = "@" + quote(f"{name[1:]}@{version}", safe="@")

    def fetch():
        return request_json("GET", f"https://registry.npmjs.org/-/npm/v1/attestations/{spec}", max_bytes=4 * 1024 * 1024) or {"attestations": []}
    value, origin, _ = ictx.lookup("npm", f"npm:att:{name}@{version}", fetch)
    return value, origin


def verify_package(ictx: IntelContext, pkg: Package, registry_meta: Optional[dict]) -> dict:
    """Return a provenance verdict dict for one npm package version."""
    out = {"status": "unavailable", "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    data, origin = fetch_attestations(ictx, pkg.name, pkg.version)
    out["origin"] = origin
    if data is None:
        out["reason"] = "Attestation could not be retrieved (registry unavailable and nothing cached)."
        return out
    att = next((a for a in data.get("attestations") or [] if a.get("predicateType") == SLSA_V1), None)
    if not att:
        out.update(status="absent", reason="No SLSA provenance attestation is published for this version.")
        return out
    try:
        from sigstore.models import Bundle
        from sigstore.verify import policy
    except ImportError:
        out.update(status="unavailable", reason="sigstore library not installed.")
        return out
    bundle_json = att.get("bundle") or {}
    try:
        raw_payload = base64.b64decode(bundle_json["dsseEnvelope"]["payload"])
        claimed = json.loads(raw_payload)
        pred = claimed.get("predicate") or {}
        wf = ((pred.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow") or {}
        repo_url = wf.get("repository")
        deps = (pred.get("buildDefinition") or {}).get("resolvedDependencies") or []
        commit = ((deps[0] if deps else {}).get("digest") or {}).get("gitCommit")
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        out.update(status="invalid", reason="Attestation is malformed.")
        return out
    if not repo_url or not str(repo_url).startswith("https://github.com/") or not commit:
        out.update(status="unsupported", reason="Only GitHub Actions provenance is verified in this version "
                                                "(statement does not name a GitHub repository and commit).",
                   repository=repo_url)
        return out
    verifier, mode = _get_verifier(ictx.offline)
    pol = policy.AllOf([policy.OIDCIssuer(GITHUB_ISSUER), policy.OIDCSourceRepositoryURI(repo_url),
                        policy.OIDCSourceRepositoryDigest(commit)])
    try:
        bundle = Bundle.from_json(json.dumps(bundle_json))
        payload_type, payload = verifier.verify_dsse(bundle, pol)
        statement = json.loads(payload)            # use ONLY the verified bytes from here on
    except Exception as exc:  # sigstore raises several error types; any failure = not verified
        out.update(status="invalid", reason=f"Sigstore verification failed: {str(exc)[:200]}", trust_root=mode)
        return out
    subj = next((s for s in statement.get("subject") or [] if s.get("name") == f"pkg:npm/{pkg.name}@{pkg.version}"), None)
    want_hex = _sri_to_hex(pkg.integrity) or _sri_to_hex(((registry_meta or {}).get("versions") or {}).get(pkg.version, {}).get("integrity"))
    tlog = ((bundle_json.get("verificationMaterial") or {}).get("tlogEntries") or [{}])[0]
    pred = statement.get("predicate") or {}
    run = ((pred.get("runDetails") or {}).get("metadata") or {}).get("invocationId")
    out.update({
        "repository": repo_url, "commit": commit, "workflow": wf.get("path"), "ref": wf.get("ref"),
        "builder": ((pred.get("runDetails") or {}).get("builder") or {}).get("id"), "run_url": run,
        "rekor_log_index": tlog.get("logIndex"),
        "rekor_url": f"https://search.sigstore.dev/?logIndex={tlog.get('logIndex')}" if tlog.get("logIndex") else None,
        "signed_at": datetime.fromtimestamp(int(tlog["integratedTime"]), timezone.utc).isoformat(timespec="seconds")
        if str(tlog.get("integratedTime", "")).isdigit() else None,
        "trust_root": mode, "digest_source": "lockfile" if _sri_to_hex(pkg.integrity) else "registry",
    })
    if not subj:
        out.update(status="invalid", reason="Verified statement is about a different package/version.")
        return out
    if not want_hex:
        out.update(status="invalid", reason="No SHA-512 hash available to bind the attestation to the installed artifact.")
        return out
    if (subj.get("digest") or {}).get("sha512") != want_hex:
        out.update(status="invalid", reason="Attested SHA-512 does not match the artifact hash in the lockfile/registry: "
                                            "the installed tarball is not the one that was built.")
        return out
    declared = _norm_repo((registry_meta or {}).get("repository"))
    if declared and declared != _norm_repo(repo_url):
        out.update(status="repo_mismatch", declared_repository=declared,
                   reason=f"Signature is valid, but the package declares {declared} while it was built from {_norm_repo(repo_url)}.")
        return out
    out.update(status="verified", reason=f"Built from {repo_url} at commit {commit[:12]} by {wf.get('path')} "
                                         f"({wf.get('ref')}); Sigstore signature, certificate identity and "
                                         f"transparency-log entry verified; artifact hash matches.")
    return out


def to_finding(pkg: Package, v: dict) -> Optional[dict]:
    from .analyzers.heuristics import signal
    if v["status"] == "invalid":
        f = signal("provenance_invalid", "Build provenance failed verification", "high", "high",
                   f"{pkg.name}@{pkg.version}: {v.get('reason')}", "Sigstore verification of npm SLSA provenance",
                   "A published attestation that does not verify (bad signature, wrong identity, or a hash that does not "
                   "match the installed artifact) can indicate a tampered package or lockfile. Do not install until explained.",
                   "Provenance", finding_kind="integrity")
    elif v["status"] == "repo_mismatch":
        f = signal("provenance_repo_mismatch", "Built from a different repository than declared", "medium", "high",
                   f"{pkg.name}@{pkg.version}: {v.get('reason')}", "Sigstore-verified provenance vs registry metadata",
                   "Legitimate after repository moves/forks, but also how hijacked packages are published from an "
                   "attacker's repository. Confirm the build repository is the project's official one.",
                   "Provenance", finding_kind="integrity")
    else:
        return None
    f["package_id"] = pkg.id
    f["provenance"] = v
    return f
