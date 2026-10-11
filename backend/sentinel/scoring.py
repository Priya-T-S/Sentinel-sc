"""Explainable risk scoring.

Four separate values per finding (0-100 unless noted). Every contribution is recorded in
`factors` so the UI can answer "Why this score?". Missing inputs stay `None` (shown as
"Unknown") — they are never silently converted into zero risk.

1. Intrinsic risk   — how bad is this issue in the package, independent of this application?
     vulnerability: CVSS v3 base score x 10 when a vector exists; otherwise the advisory's
                    qualitative rating mapped to a band midpoint (critical 95, high 80,
                    medium 55, low 25). +10 if the CVE is in CISA KEV (known exploited),
                    capped at 100. Unknown severity -> None.
     heuristic:     fixed band per signal severity (high 70, medium 45, low 20, info 5).
2. Exposure         — how much does it matter for THIS application?
     intrinsic x reachability weight x scope weight x applicability weight
       reachability: symbol_call 1.0, imported 0.85, transitive_imported 0.7, unknown 0.7,
                     transitive 0.55, declared_not_imported 0.4
       scope:        runtime 1.0, optional/peer/unknown 0.8, build 0.6, dev/test 0.35
       applicability: local range check disagrees with OSV -> 0.6
     These weights are an explicit, documented ordering of evidence strength — not a
     statistical model. They can be audited and changed in one place (below).
3. Confidence       — how sure is the assessment? (high / medium / low + 0-100)
     starts at 50; +20 exact version from lockfile, +15 advisory details retrieved,
     +10 local range evaluation agrees, -20 local range evaluation disagrees,
     -15 data came from a stale cache or fixture, -10 reachability unknown.
4. Priority         — what to fix first? (P1..P4 + 0-100)
     exposure + 10 if a verified fix exists + 15 if known-exploited (KEV)
     + 10 x EPSS probability (0..1), capped at 100.
     P1 >= 75, P2 >= 55, P3 >= 30, else P4.

Correlated signals are not double counted: aliased advisories are merged before scoring
(one flaw = one finding), and the package-level score is the MAX of its findings, not a sum.
"""
from __future__ import annotations

from typing import Optional

SEV_BAND = {"critical": 95, "high": 80, "medium": 55, "low": 25, "info": 5}
HEUR_BAND = {"critical": 85, "high": 70, "medium": 45, "low": 20, "info": 5}
REACH_W = {"symbol_call": 1.0, "imported": 0.85, "transitive_imported": 0.7, "unknown": 0.7,
           "transitive": 0.55, "declared_not_imported": 0.4}
SCOPE_W = {"runtime": 1.0, "optional": 0.8, "peer": 0.8, "unknown": 0.8, "build": 0.6, "dev": 0.35, "test": 0.35}


def _bucket(p: Optional[float]) -> str:
    if p is None:
        return "unknown"
    return "P1" if p >= 75 else "P2" if p >= 55 else "P3" if p >= 30 else "P4"


def score_vulnerability(f: dict, pkg_scope: str, version_exact: bool, kev: Optional[dict], epss: Optional[dict],
                        fix_verified: bool) -> dict:
    adv = f["advisory"]
    factors = []
    # ---- intrinsic
    if adv.get("cvss_score") is not None:
        intrinsic = adv["cvss_score"] * 10
        factors.append({"component": "intrinsic", "factor": "CVSS v3 base score", "value": f"{adv['cvss_score']}",
                        "effect": f"= {intrinsic:.0f}", "evidence": adv.get("cvss_vector")})
    elif adv.get("severity") in SEV_BAND:
        intrinsic = SEV_BAND[adv["severity"]]
        factors.append({"component": "intrinsic", "factor": "Advisory severity rating", "value": adv["severity"],
                        "effect": f"= {intrinsic} (band midpoint)", "evidence": adv.get("severity_basis")})
    else:
        intrinsic = None
        factors.append({"component": "intrinsic", "factor": "Severity", "value": "unknown",
                        "effect": "intrinsic risk unknown", "evidence": "Advisory has no CVSS vector or rating"})
    if kev and intrinsic is not None:
        intrinsic = min(100.0, intrinsic + 10)
        factors.append({"component": "intrinsic", "factor": "Known exploited (CISA KEV)", "value": kev.get("cve"),
                        "effect": "+10", "evidence": f"Added to KEV {kev.get('dateAdded')}"})
    # ---- exposure
    reach = (f.get("reachability") or {}).get("level", "unknown")
    rw, sw = REACH_W.get(reach, 0.7), SCOPE_W.get(pkg_scope, 0.8)
    aw = 0.6 if adv.get("applies_to_installed") is False else 1.0
    exposure = None if intrinsic is None else intrinsic * rw * sw * aw
    factors.append({"component": "exposure", "factor": "Reachability evidence", "value": reach, "effect": f"x {rw}",
                    "evidence": (f.get("reachability") or {}).get("label")})
    factors.append({"component": "exposure", "factor": "Dependency scope", "value": pkg_scope, "effect": f"x {sw}",
                    "evidence": "from lockfile/manifest"})
    if aw != 1.0:
        factors.append({"component": "exposure", "factor": "Range check disagrees with OSV", "value": "disputed",
                        "effect": f"x {aw}", "evidence": "Local range evaluation did not confirm the match"})
    paths = f.get("paths") or []
    factors.append({"component": "exposure", "factor": "Dependency depth / breadth", "value":
                    f"depth {min((len(p) - 1 for p in paths), default='?')}, {len(paths)} path(s), {f.get('blast_radius', {}).get('roots', 0)} component(s)",
                    "effect": "informational (shown in blast radius; not multiplied, to avoid double counting with reachability)",
                    "evidence": None})
    # ---- confidence
    conf = 50
    notes = []
    if version_exact:
        conf += 20; notes.append("+20 exact version from lockfile/pin")
    else:
        notes.append("+0 version not exact")
    if adv.get("summary") or adv.get("details"):
        conf += 15; notes.append("+15 advisory details retrieved")
    if adv.get("applies_to_installed") is True:
        conf += 10; notes.append("+10 local range evaluation agrees")
    elif adv.get("applies_to_installed") is False:
        conf -= 20; notes.append("-20 local range evaluation disagrees")
    origins = adv.get("origin") or []
    if any(o in ("stale", "fixture") for o in origins):
        conf -= 15; notes.append("-15 data from stale cache or versioned fixture")
    if reach == "unknown":
        conf -= 10; notes.append("-10 reachability unknown")
    conf = max(0, min(100, conf))
    factors.append({"component": "confidence", "factor": "Evidence quality", "value": conf, "effect": "; ".join(notes), "evidence": None})
    # ---- priority
    if exposure is None:
        priority = None
    else:
        priority = exposure
        if fix_verified:
            priority += 10
            factors.append({"component": "priority", "factor": "Verified fix available", "value": "yes", "effect": "+10",
                            "evidence": "Fixed version confirmed by OSV re-query"})
        if kev:
            priority += 15
            factors.append({"component": "priority", "factor": "Known exploited", "value": "KEV", "effect": "+15", "evidence": None})
        if epss and epss.get("epss") is not None:
            priority += 10 * float(epss["epss"])
            factors.append({"component": "priority", "factor": "EPSS probability", "value": f"{float(epss['epss']):.3f}",
                            "effect": f"+{10 * float(epss['epss']):.1f}", "evidence": f"FIRST EPSS {epss.get('date')}"})
        priority = min(100.0, priority)
    return {
        "intrinsic": None if intrinsic is None else round(intrinsic, 1),
        "exposure": None if exposure is None else round(exposure, 1),
        "confidence": conf,
        "confidence_label": "high" if conf >= 75 else "medium" if conf >= 50 else "low",
        "priority": None if priority is None else round(priority, 1),
        "priority_bucket": _bucket(priority),
        "factors": factors,
    }


def score_signal(f: dict, pkg_scope: str) -> dict:
    sev = f.get("severity", "low")
    intrinsic = HEUR_BAND.get(sev, 20)
    sw = SCOPE_W.get(pkg_scope, 0.8) if f.get("package_id") else 1.0
    conf_map = {"high": 80, "medium": 60, "low": 40}
    conf = conf_map.get(f.get("confidence", "medium"), 60)
    exposure = intrinsic * sw
    priority = exposure * (conf / 100)
    factors = [
        {"component": "intrinsic", "factor": "Heuristic signal severity", "value": sev, "effect": f"= {intrinsic}",
         "evidence": "Fixed band per severity (heuristics are not CVSS-scored)"},
        {"component": "exposure", "factor": "Dependency scope", "value": pkg_scope if f.get("package_id") else "repository",
         "effect": f"x {sw}", "evidence": None},
        {"component": "priority", "factor": "Signal confidence", "value": f.get("confidence"), "effect": f"x {conf / 100:.2f}",
         "evidence": "Heuristic priority is discounted by its confidence"},
    ]
    return {"intrinsic": intrinsic, "exposure": round(exposure, 1), "confidence": conf,
            "confidence_label": f.get("confidence", "medium"), "priority": round(priority, 1),
            "priority_bucket": _bucket(priority), "factors": factors}


def package_risk(findings: list[dict]) -> dict:
    """Package-level summary: MAX of finding scores (never a sum)."""
    vals = [f["scores"] for f in findings if f.get("scores")]
    def mx(k):
        xs = [v[k] for v in vals if v.get(k) is not None]
        return max(xs) if xs else None
    return {"intrinsic": mx("intrinsic"), "exposure": mx("exposure"), "priority": mx("priority"),
            "priority_bucket": _bucket(mx("priority")) if vals else "none"}
