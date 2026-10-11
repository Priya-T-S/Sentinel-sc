"""Transparent supply-chain heuristics.

Each signal records: observation, source, severity, confidence and explanation. Signals are
evidence for review — none of them, alone or combined, is presented as confirmed malware.
Missing metadata is reported as "unknown", never as a risk in itself.
"""
from __future__ import annotations

import base64
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from .. import versions
from ..intel.registry import days_since, host_of
from ..models import DependencyGraph, Package
from ..reposource import RepoSource
from .popular import POPULAR

DEFAULT_REGISTRY = {"npm": {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"},
                    "PyPI": {"pypi.org", "files.pythonhosted.org"}}


def signal(kind: str, title: str, severity: str, confidence: str, observation: str, source: str,
           explanation: str, category: str = "Suspicious package signal", evidence: Optional[list] = None,
           finding_kind: str = "suspicious") -> dict:
    return {"kind": finding_kind, "signal": kind, "category": category, "title": title, "severity": severity,
            "confidence": confidence, "verified": False,
            "observation": observation, "explanation": explanation,
            "evidence": [{"observation": observation, "source": source, "origin": "computed"}] + (evidence or [])}


# --------------------------------------------------------------------------- typosquatting

def _dl_distance(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein (optimal string alignment), early exit above cap."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2 = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


_HOMOGLYPHS = [("rn", "m"), ("0", "o"), ("1", "l"), ("vv", "w"), ("-", ""), ("_", ""), (".", ""), ("js", "")]


def _skeleton(name: str) -> str:
    s = name.lower()
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def typosquat_target(ecosystem: str, name: str) -> Optional[tuple[str, str]]:
    pop = POPULAR.get(ecosystem)
    if not pop or name in pop:
        return None
    bare = name.split("/", 1)[1] if name.startswith("@") and "/" in name else name
    if len(bare) < 4:
        return None
    for p in pop:
        if p == bare:
            # scope squatting: "@evil/lodash" mirrors unscoped "lodash"
            return (p, "scoped copy of a popular unscoped package name") if name.startswith("@") else None
        if abs(len(p) - len(bare)) > 2:
            continue
        d = _dl_distance(bare.lower(), p.lower(), 2)
        if d == 1 or (d == 2 and len(p) >= 8):
            return p, f"edit distance {d}"
        if _skeleton(bare) == _skeleton(p):
            return p, "visually confusable / separator variant"
    return None


# --------------------------------------------------------------------------- source inspection

_SRC_PATTERNS = [
    ("dynamic_eval", re.compile(r"\beval\s*\(|new\s+Function\s*\("), "Dynamic code execution (eval / new Function)", "high"),
    ("decode_exec", re.compile(r"Buffer\.from\([^)]*['\"]base64['\"]\)|atob\s*\(|base64\.b64decode\("), "Runtime decoding of embedded data", "medium"),
    ("child_process", re.compile(r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|\bexecSync\s*\(|\bspawn\s*\(|subprocess\.(Popen|run|call)|os\.system\("), "Process execution", "high"),
    ("network", re.compile(r"require\(\s*['\"](?:node:)?(?:https?|net|dns|dgram)['\"]\s*\)|\bfetch\s*\(\s*['\"]https?://|urllib\.request|requests\.(get|post)\(|socket\.socket\("), "Network access", "medium"),
    ("env_access", re.compile(r"process\.env(?!\.NODE_ENV\b)(?:\[|\.|\))|JSON\.stringify\(\s*process\.env|os\.environ"), "Environment variable access", "medium"),
    ("sensitive_files", re.compile(r"\.ssh/|id_rsa|\.npmrc|\.aws/credentials|\.bash_history|/etc/passwd|\.git-credentials"), "References to credential files", "high"),
    ("hex_or_b64_blob", re.compile(r"['\"][A-Za-z0-9+/=]{200,}['\"]|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){30,}"), "Large encoded string literal", "medium"),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def inspect_package_source(src: RepoSource, base: str, max_files: int = 60) -> list[dict]:
    """Static, bounded inspection of a package directory present in the scanned input.
    Code is read as text only — never executed or imported."""
    hits: list[dict] = []
    files = [f for f in src.list_files() if f.startswith(base.rstrip("/") + "/")
             and f.endswith((".js", ".cjs", ".mjs", ".ts", ".py", ".sh", "package.json"))][:max_files]
    for f in files:
        text = src.read_text(f, 512 * 1024)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines()[:20000], 1):
            if len(line) > 5000:
                line_ent = _entropy(line[:5000])
                if line_ent > 5.0:
                    hits.append({"pattern": "minified_or_obfuscated", "label": "Very long high-entropy line (obfuscation indicator)",
                                 "severity": "medium", "file": f, "line": lineno, "snippet": line[:120] + "..."})
                    continue
            for key, rx, label, sev in _SRC_PATTERNS:
                if rx.search(line):
                    hits.append({"pattern": key, "label": label, "severity": sev, "file": f, "line": lineno,
                                 "snippet": line.strip()[:160]})
        if len(hits) > 80:
            break
    return hits


def _decode_preview(snippet: str) -> Optional[str]:
    m = re.search(r"Buffer\.from\(\s*['\"]([A-Za-z0-9+/=]{8,400})['\"]", snippet)
    if not m:
        return None
    try:
        out = base64.b64decode(m.group(1), validate=True).decode("utf-8", errors="replace")
    except (ValueError, base64.binascii.Error):
        return None
    return "".join(ch if ch.isprintable() else "?" for ch in out)[:120]


# --------------------------------------------------------------------------- main analysis

def analyze_package(pkg: Package, graph: DependencyGraph, meta: Optional[dict], meta_origin: str,
                    src: RepoSource, now: Optional[datetime] = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    out: list[dict] = []
    vmeta = (meta or {}).get("versions", {}).get(pkg.version or "", {}) if meta else {}

    # ---- typosquatting
    t = typosquat_target(pkg.ecosystem, pkg.name)
    if t:
        target, why = t
        # Name similarity alone is weak. Escalate only when corroborated by other evidence.
        created_days = days_since((meta or {}).get("created"), now) if meta else None
        corroborating = []
        if pkg.direct:
            corroborating.append("declared directly by the application")
        if pkg.has_install_script or vmeta.get("install_scripts"):
            corroborating.append("runs install-time scripts")
        if created_days is not None and created_days < 90:
            corroborating.append(f"first published {created_days:.0f} days ago")
        if pkg.source_type != "registry":
            corroborating.append(f"not installed from the public registry ({pkg.source_type})")
        established = created_days is not None and created_days > 730 and len((meta or {}).get("versions") or {}) >= 3
        if established and not pkg.has_install_script and not pkg.direct:
            sev, conf = "info", "low"
            ctx_note = (f" However, '{pkg.name}' has been published for {created_days / 365:.1f} years with "
                        f"{len(meta.get('versions') or {})} versions, which suggests an established, distinct package.")
        elif len(corroborating) >= 2:
            sev, conf, ctx_note = "high", "medium", " Corroborating evidence: " + "; ".join(corroborating) + "."
        elif corroborating:
            sev, conf, ctx_note = "medium", "low", " Corroborating evidence: " + "; ".join(corroborating) + "."
        else:
            sev, conf, ctx_note = "low", "low", " No corroborating evidence was found."
        out.append(signal("typosquat", f"Name resembles popular package '{target}'", sev, conf,
                          f"'{pkg.name}' is similar to '{target}' ({why}).{ctx_note}",
                          "Name similarity check against a bundled list of high-download packages",
                          "Typosquats rely on mistyped install commands. Similarity alone does not prove intent; "
                          "verify the package is the one you meant to install.", "Typosquatting"))

    # ---- install-time scripts
    scripts = vmeta.get("install_scripts") or {}
    if pkg.has_install_script or scripts:
        detail = ", ".join(f"{k}: {v}" for k, v in scripts.items()) if scripts else "lockfile flag hasInstallScript=true"
        out.append(signal("install_script", "Runs code at install time", "medium", "high",
                          f"{pkg.name}@{pkg.version} declares install lifecycle scripts ({detail[:200]}).",
                          "Lockfile 'hasInstallScript' / registry version manifest",
                          "Install scripts execute with the installing user's privileges before any code review. "
                          "Many legitimate packages (native builds) use them; malicious packages commonly do too. "
                          "Consider `--ignore-scripts` and an allow-list.", "Install-time execution"))

    # ---- local / git / url sources
    if pkg.source_type == "file":
        out.append(signal("local_source", "Dependency installed from a local path", "low", "high",
                          f"{pkg.name} resolves to a local directory ({pkg.local_path or pkg.resolved}).",
                          "Lockfile 'link'/'file:' entry",
                          "Local packages bypass registry integrity and provenance checks; they are reviewed only if "
                          "their source is in this repository.", "Provenance", finding_kind="integrity"))
    elif pkg.source_type in ("git", "url"):
        mutable = not re.search(r"[#@/][0-9a-f]{40}\b", pkg.resolved or "")
        out.append(signal("non_registry_source", f"Dependency fetched from {'git' if pkg.source_type == 'git' else 'a direct URL'}",
                          "medium" if mutable else "low", "high",
                          f"{pkg.name} resolves to {(pkg.resolved or '')[:120]}" + (" (no immutable commit SHA)" if mutable else ""),
                          "Lockfile resolved field",
                          "Git/URL dependencies skip registry integrity metadata; branch or tag references can be "
                          "moved to different code after review.", "Provenance", finding_kind="integrity"))

    # ---- integrity metadata (registry packages in lockfiles)
    if pkg.version_exact and pkg.source_type == "registry" and pkg.ecosystem in ("npm", "crates.io", "NuGet") and pkg.resolved is not None:
        if not pkg.integrity:
            out.append(signal("missing_integrity", "No integrity hash in lockfile", "medium", "high",
                              f"Lockfile entry for {pkg.name}@{pkg.version} has no integrity/checksum.",
                              "Lockfile", "Without a hash the package manager cannot detect a substituted artifact.",
                              "Integrity", finding_kind="integrity"))
        elif pkg.integrity.startswith("sha1-"):
            out.append(signal("weak_integrity", "Lockfile uses SHA-1 integrity only", "low", "high",
                              f"{pkg.name}@{pkg.version} integrity is SHA-1.", "Lockfile",
                              "SHA-1 is collision-prone; regenerate the lockfile with a modern npm to record SHA-512.",
                              "Integrity", finding_kind="integrity"))
        elif vmeta.get("integrity") and pkg.integrity.startswith("sha512-") and vmeta["integrity"] != pkg.integrity:
            out.append(signal("integrity_mismatch", "Lockfile hash differs from registry hash", "high", "high",
                              f"Lockfile integrity for {pkg.name}@{pkg.version} does not match the registry's dist.integrity.",
                              "Lockfile vs npm registry",
                              "A mismatch can indicate lockfile tampering, a private mirror serving different bytes, or "
                              "artifact substitution. Investigate before installing.", "Integrity", finding_kind="integrity"))

    # ---- registry/resolution host (dependency confusion indicators)
    host = host_of(pkg.resolved) if pkg.resolved and pkg.resolved.startswith("http") else None
    if host and pkg.ecosystem in DEFAULT_REGISTRY and host not in DEFAULT_REGISTRY[pkg.ecosystem] and pkg.source_type == "registry":
        out.append(signal("alt_registry", "Resolved from a non-default registry", "low", "high",
                          f"{pkg.name} was resolved from {host}.", "Lockfile resolved URL",
                          "Mixed registries enable dependency-confusion attacks if a public package can shadow an internal one. "
                          "Confirm the registry is intended and scoped.", "Dependency confusion"))
    if pkg.resolved and pkg.resolved.startswith("http://"):
        out.append(signal("insecure_transport", "Resolved over plain HTTP", "high", "high",
                          f"{pkg.name} resolved URL uses http://", "Lockfile resolved URL",
                          "Unencrypted downloads can be modified in transit.", "Integrity", finding_kind="integrity"))

    # ---- registry metadata signals (only when metadata exists)
    if meta:
        created_days = days_since(meta.get("created"), now)
        pub_days = days_since(vmeta.get("published"), now) if vmeta else None
        if created_days is not None and created_days < 30:
            out.append(signal("new_package", "Package is less than 30 days old", "medium", "high",
                              f"{pkg.name} was first published {created_days:.0f} day(s) ago ({meta.get('created')}).",
                              f"{pkg.ecosystem} registry metadata ({meta_origin})",
                              "Most malicious packages are removed within days; very new packages deserve review.",
                              "Package reputation"))
        if pub_days is not None and pub_days < 7:
            out.append(signal("fresh_release", "Installed version published within the last 7 days", "low", "high",
                              f"{pkg.name}@{pkg.version} was published {pub_days:.1f} day(s) ago.",
                              f"{pkg.ecosystem} registry metadata ({meta_origin})",
                              "Compromised-maintainer attacks ship as fresh releases; a short cooldown before adopting "
                              "new versions reduces exposure.", "Release pattern"))
        if vmeta.get("deprecated"):
            out.append(signal("deprecated", "Installed version is deprecated", "medium", "high",
                              f"Registry deprecation notice: {vmeta['deprecated'][:200]}",
                              "npm registry version manifest",
                              "Deprecated versions are usually no longer patched.", "Maintenance", finding_kind="maintenance"))
        if vmeta.get("yanked"):
            out.append(signal("yanked", "Installed version was yanked", "medium", "high",
                              f"{pkg.name}=={pkg.version} is marked yanked on PyPI.", "PyPI JSON API",
                              "Maintainers yank releases that are broken or unsafe.", "Maintenance", finding_kind="maintenance"))
        # release burst / unmaintained
        pubs = sorted(d["published"] for d in (meta.get("versions") or {}).values() if d.get("published"))
        if pubs:
            last_days = days_since(pubs[-1], now)
            if last_days is not None and last_days > 730:
                out.append(signal("unmaintained", "No releases in over 2 years", "low", "medium",
                                  f"Latest release of {pkg.name} was {last_days / 365:.1f} years ago ({pubs[-1][:10]}).",
                                  f"{pkg.ecosystem} registry metadata ({meta_origin})",
                                  "Inactive projects may not ship security fixes. Stable, 'finished' libraries can also be "
                                  "inactive, so this is a maintenance signal, not a vulnerability.", "Maintenance",
                                  finding_kind="maintenance"))
            burst = _release_burst(pubs)
            if burst:
                out.append(signal("release_burst", "Unusual burst of releases", "low", "medium",
                                  f"{burst[0]} versions of {pkg.name} were published within 24 hours (around {burst[1][:10]}).",
                                  f"{pkg.ecosystem} registry metadata ({meta_origin})",
                                  "Rapid successive releases can accompany account takeovers or spam campaigns, but also "
                                  "legitimate CI-driven releases.", "Release pattern"))
        if meta.get("repository") is None and pkg.direct:
            out.append(signal("no_repository", "No source repository declared", "info", "medium",
                              f"Registry metadata for {pkg.name} lists no source repository.",
                              f"{pkg.ecosystem} registry metadata ({meta_origin})",
                              "Without a repository link the published artifact cannot be compared to source.", "Provenance",
                              finding_kind="integrity"))
        # publisher change between versions (npm only, when both known)
        if pkg.ecosystem == "npm" and vmeta.get("publisher"):
            prev = _previous_publisher(meta, pkg.version)
            if prev and prev != vmeta["publisher"]:
                out.append(signal("publisher_change", "Publisher changed for this version", "low", "medium",
                                  f"{pkg.name}@{pkg.version} was published by '{vmeta['publisher']}'; the previous version by '{prev}'.",
                                  "npm registry _npmUser", "Publisher changes are common in teams but also occur after "
                                  "account takeovers. Check the project's announcements.", "Ownership"))
    return out


def _release_burst(pubs: list[str]) -> Optional[tuple[int, str]]:
    times = []
    for p in pubs[-300:]:
        try:
            times.append(datetime.fromisoformat(p.replace("Z", "+00:00")))
        except ValueError:
            continue
    j = 0
    best = (0, "")
    for i in range(len(times)):
        while (times[i] - times[j]).total_seconds() > 86400:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, times[i].isoformat())
    return best if best[0] >= 10 else None


def _previous_publisher(meta: dict, version: str) -> Optional[str]:
    vs = meta.get("versions") or {}
    ordered = versions.sort_versions("npm", [v for v in vs if not versions.is_prerelease("npm", v)])
    if version not in ordered:
        return None
    idx = ordered.index(version)
    if idx == 0:
        return None
    return vs[ordered[idx - 1]].get("publisher")


def source_signals(pkg: Package, src: RepoSource) -> list[dict]:
    """Inspect package source that is present in the scanned input (vendored / file: / node_modules)."""
    bases = []
    if pkg.local_path:
        bases.append(pkg.local_path)
    if pkg.ecosystem == "npm":
        nm = f"node_modules/{pkg.name}"
        if src.exists(nm + "/package.json"):
            bases.append(nm)
    out = []
    for base in bases:
        hits = inspect_package_source(src, base)
        if not hits:
            continue
        by_pat: dict[str, list[dict]] = {}
        for h in hits:
            by_pat.setdefault(h["pattern"], []).append(h)
        sev = "high" if {"dynamic_eval", "child_process", "sensitive_files"} & set(by_pat) and len(by_pat) >= 2 else "medium"
        ev = []
        for pat, hs in by_pat.items():
            for h in hs[:3]:
                prev = _decode_preview(h["snippet"]) if pat == "decode_exec" else None
                ev.append({"observation": f"{h['label']}: {h['file']}:{h['line']}", "snippet": h["snippet"],
                           "decoded_preview": prev, "source": "Static source inspection (text only, not executed)",
                           "file": h["file"], "line": h["line"], "origin": "computed"})
        labels = sorted({h["label"] for h in hits})
        out.append(signal("source_patterns", f"Risky code patterns in package source ({len(labels)} type(s))", sev, "medium",
                          f"{pkg.name} source contains: {'; '.join(labels)}.",
                          "Static pattern inspection of package files included in the scanned input",
                          "Combinations of dynamic execution, decoding, environment access and network calls are typical of "
                          "credential-stealing packages. Each pattern also has legitimate uses — review the cited lines.",
                          "Malicious code indicators", evidence=ev))
    return out


def repo_level_findings(ctx, graph: DependencyGraph) -> list[dict]:
    out = []
    for m in ctx.missing_lockfiles:
        out.append({**signal("missing_lockfile", f"No lockfile for {m['manifest']}", "medium", "high",
                             f"{m['manifest']} ({m['ecosystem']}) has no lockfile in the same directory.",
                             "Manifest discovery",
                             "Without a lockfile, every install may resolve different versions, so scans cannot verify what "
                             "is actually deployed and new malicious releases can enter silently.",
                             "Reproducibility", finding_kind="hygiene"), "file": m["manifest"]})
    for u in ctx.unpinned:
        sev = "medium" if ("git" in u["reason"] or "URL" in u["reason"] or "wildcard" in u["reason"] or "ambiguous" in u["reason"]) else "low"
        out.append({**signal("unpinned", f"Unpinned dependency: {u['name']}", sev, "high",
                             f"{u['file']}: {u['name']} '{u['spec']}' - {u['reason']}.", "Manifest parser",
                             "Floating or mutable references let the resolved code change without a manifest change.",
                             "Pinning", finding_kind="hygiene"), "file": u["file"], "name": u["name"]})
    for d in ctx.drift:
        out.append({**signal("lockfile_drift", f"Lockfile drift: {d['name']}", "medium", "high",
                             f"{d['file']}: {d['name']} declared '{d['declared']}', locked {d['locked'] or '(missing)'} - {d['issue']}.",
                             "Manifest vs lockfile comparison",
                             "A lockfile out of sync with its manifest means installs may not match what was reviewed; "
                             "it can also indicate manual lockfile edits.", "Lockfile drift", finding_kind="integrity"),
                    "file": d["file"], "name": d["name"]})
    scoped = {r["scope"]: r for r in ctx.registries if r.get("scope")}
    for r in ctx.registries:
        if r["kind"] == "pip-extra-index":
            out.append({**signal("extra_index_url", "pip --extra-index-url in use", "high", "high",
                                 f"{r['file']} adds an extra package index ({r['url']}).", "requirements file",
                                 "pip merges all indexes and picks the highest version, so a public package with an internal "
                                 "name can shadow the private one (dependency confusion). Use --index-url with a proxy that "
                                 "prefers internal packages, or pin with hashes.", "Dependency confusion"), "file": r["file"]})
        if r.get("insecure"):
            out.append({**signal("insecure_index", "Package index uses plain HTTP", "high", "high",
                                 f"{r['file']} references an http:// index ({r['url']}).", "Configuration",
                                 "Packages fetched over HTTP can be replaced in transit.", "Integrity", finding_kind="integrity"),
                        "file": r["file"]})
        if r["kind"] == "npm-token-literal":
            out.append({**signal("npmrc_token", "Literal auth token in .npmrc", "high", "high",
                                 f"{r['file']} contains an _authToken value that is not an environment variable reference.",
                                 ".npmrc", "Registry tokens in source control allow package publication or private package "
                                 "theft. Use ${NPM_TOKEN} and rotate the token.", "Secrets", finding_kind="hygiene"),
                        "file": r["file"]})
    for scope, r in scoped.items():
        for p in graph.packages.values():
            if p.ecosystem == "npm" and p.name.startswith(scope + "/") and p.resolved:
                h = host_of(p.resolved)
                expected = host_of(r["url"]) if r["url"] and "://" in r["url"] else r["url"]
                if h and expected and h != expected:
                    out.append({**signal("scope_registry_mismatch", f"{p.name} resolved outside its scoped registry", "high", "high",
                                         f".npmrc maps {scope} to {expected}, but the lockfile resolved {p.name} from {h}.",
                                         ".npmrc vs lockfile",
                                         "This is the signature of a dependency-confusion substitution: an internal scoped "
                                         "package was fetched from a different registry.", "Dependency confusion"),
                                "package_id": p.id})
    return out
