"""Deterministic, auditable security-gate policy evaluation.

The same result + policy always yields the same verdict. No AI or network involvement.
Verdict: "fail" (exit code 1) | "warn" (exit 0, or 3 with --strict-warn) | "pass" (exit 0).
"""
from __future__ import annotations

import copy
from typing import Optional

from . import db
from .models import SEVERITY_ORDER

DEFAULT_POLICY = {
    "version": 1,
    "fail_on_vulnerability_severity": "critical",   # fail on verified vulns at/above this severity
    "fail_min_confidence": "medium",                 # ...only when assessment confidence >= this
    "fail_only_if_fix_available": False,
    "fail_on_known_exploited": True,                 # any verified vuln listed in CISA KEV fails
    "warn_on_vulnerability_severity": "medium",
    "warn_on_signal_severity": "medium",             # heuristic / integrity / CI / secret findings
    "fail_on_signal_kinds": ["ci_pwn_request", "secret_private_key", "integrity_mismatch", "scope_registry_mismatch"],
    "require_lockfile": True,                        # missing lockfile -> warn (or fail if strict_lockfile)
    "strict_lockfile": False,
    "flag_unpinned": True,
    "fail_on_intelligence_unavailable": True,        # provider failed/offline without data: never pass as "clean"
    "fail_on_unverified_packages": False,            # packages with no exact version (ranges, no lockfile)
    "ignore_dev_dependencies": False,
    "disallowed_licenses": [],                       # enforced only where license metadata exists
    "ignored_advisories": [],                        # explicit, auditable exceptions (advisory IDs)
}

CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


def current_policy() -> dict:
    stored = db.get_settings().get("policy")
    pol = copy.deepcopy(DEFAULT_POLICY)
    if isinstance(stored, dict):
        pol.update({k: v for k, v in stored.items() if k in DEFAULT_POLICY})
    return pol


def validate(policy: dict) -> dict:
    out = copy.deepcopy(DEFAULT_POLICY)
    for k, v in (policy or {}).items():
        if k not in DEFAULT_POLICY:
            raise ValueError(f"Unknown policy key: {k}")
        dv = DEFAULT_POLICY[k]
        if isinstance(dv, bool) and not isinstance(v, bool):
            raise ValueError(f"{k} must be true/false")
        if isinstance(dv, list) and not (isinstance(v, list) and all(isinstance(x, str) and len(x) < 100 for x in v) and len(v) < 500):
            raise ValueError(f"{k} must be a list of strings")
        if k.endswith("severity") and v not in ("critical", "high", "medium", "low", "none"):
            raise ValueError(f"{k} must be critical|high|medium|low|none")
        if k == "fail_min_confidence" and v not in CONF_ORDER:
            raise ValueError("fail_min_confidence must be low|medium|high")
        out[k] = v
    return out


def _sev_at_least(sev: str, threshold: str) -> bool:
    if threshold == "none":
        return False
    return SEVERITY_ORDER.get(sev, -1) >= SEVERITY_ORDER[threshold]


def evaluate(result: dict, policy: Optional[dict] = None) -> dict:
    pol = validate(policy or {}) if policy is not None else current_policy()
    violations, warnings = [], []
    pk = result.get("packages", {})
    ignored = set(pol["ignored_advisories"])
    for f in result.get("findings", []):
        p = pk.get(f.get("package_id") or "", {})
        if pol["ignore_dev_dependencies"] and p.get("scope") in ("dev", "test"):
            continue
        if f["kind"] == "vulnerability":
            adv = f["advisory"]
            if ignored & set(adv.get("aliases", [])):
                continue
            conf = f["scores"].get("confidence_label", "low")
            entry = {"finding_id": f["id"], "package": f"{p.get('name')}@{p.get('version')}", "advisory": adv["id"],
                     "severity": f["severity"], "confidence": conf}
            fixable = (f.get("remediation") or {}).get("target") is not None
            if pol["fail_on_known_exploited"] and f["exploitation"].get("kev") and f["verified"]:
                violations.append({**entry, "rule": "fail_on_known_exploited", "message": f"{adv['id']} is in CISA KEV"})
            elif (f["verified"] and _sev_at_least(f["severity"], pol["fail_on_vulnerability_severity"])
                  and CONF_ORDER.get(conf, 0) >= CONF_ORDER[pol["fail_min_confidence"]]
                  and (fixable or not pol["fail_only_if_fix_available"])):
                violations.append({**entry, "rule": "fail_on_vulnerability_severity",
                                   "message": f"{f['severity']} vulnerability {adv['id']} (confidence {conf})"})
            elif _sev_at_least(f["severity"], pol["warn_on_vulnerability_severity"]):
                warnings.append({**entry, "rule": "warn_on_vulnerability_severity", "message": f"{f['severity']} vulnerability {adv['id']}"})
        else:
            sig = f.get("signal", "")
            entry = {"finding_id": f["id"], "package": p.get("name"), "signal": sig, "severity": f["severity"],
                     "confidence": f.get("confidence"), "file": f.get("file")}
            if sig in pol["fail_on_signal_kinds"] and f.get("confidence") != "low":
                violations.append({**entry, "rule": "fail_on_signal_kinds", "message": f["title"]})
            elif sig == "missing_lockfile" and pol["require_lockfile"]:
                (violations if pol["strict_lockfile"] else warnings).append({**entry, "rule": "require_lockfile", "message": f["title"]})
            elif sig in ("unpinned", "lockfile_drift") and pol["flag_unpinned"]:
                warnings.append({**entry, "rule": "flag_unpinned", "message": f["title"]})
            elif sig not in ("missing_lockfile", "unpinned") and _sev_at_least(f["severity"], pol["warn_on_signal_severity"]):
                warnings.append({**entry, "rule": "warn_on_signal_severity", "message": f["title"]})
    if pol["disallowed_licenses"]:
        bad = {l.lower() for l in pol["disallowed_licenses"]}
        for p in pk.values():
            lic = (p.get("license") or (p.get("registry") or {}).get("license") or "")
            if lic and lic.lower() in bad:
                violations.append({"rule": "disallowed_licenses", "package": f"{p['name']}@{p['version']}", "license": lic,
                                   "message": f"License {lic} is disallowed"})
    cov = result.get("coverage", {})
    unavailable = cov.get("intel_unavailable_packages", 0)
    no_exact = cov.get("no_exact_version_packages", 0)
    if unavailable:
        (violations if pol["fail_on_intelligence_unavailable"] else warnings).append(
            {"rule": "fail_on_intelligence_unavailable",
             "message": f"{unavailable} package(s) could not be checked: vulnerability intelligence unavailable"})
    if no_exact:
        (violations if pol["fail_on_unverified_packages"] else warnings).append(
            {"rule": "fail_on_unverified_packages", "message": f"{no_exact} package(s) have no exact version and could not be matched"})
    verdict = "fail" if violations else ("warn" if warnings else "pass")
    return {"verdict": verdict, "exit_code": 1 if violations else 0, "violations": violations, "warnings": warnings[:500],
            "warning_count": len(warnings), "policy": pol,
            "notes": "Deterministic evaluation of engine output; heuristics never fail a build unless listed in fail_on_signal_kinds."}
