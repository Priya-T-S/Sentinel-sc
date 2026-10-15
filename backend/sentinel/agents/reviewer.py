"""Agent 6 - Independent Security Reviewer (deterministic; optional AI explanations).

Pass 1 (claims, before scoring): every claim made by another agent must be backed by its evidence.
Unsupported claims are DOWNGRADED (never upgraded) and the correction is recorded on the finding.
Conflicting results between agents are flagged with a suggested next step.
Pass 2 (report, after the orchestrator assembles it): consistency checks on scores, counts and the
policy decision.

The reviewer can only make the report more conservative. It never adds a vulnerability, never marks a
package safe and never raises confidence.
"""
from __future__ import annotations

from typing import Optional

from .base import Board

NAME = "reviewer"

CHECKS = {
    "verified_needs_advisory": "A 'verified' vulnerability must have a retrieved advisory record, an exact installed version and no local range disagreement.",
    "clean_needs_intelligence": "A package may only be reported as checked/clean if vulnerability intelligence was actually obtained.",
    "fix_verified_needs_osv_recheck": "A 'verified' fix must have been re-queried on OSV with zero known advisories for that exact version.",
    "safe_candidate_needs_compatibility": "A 'safe candidate' fix may not cross a breaking-change boundary or leave unfixed advisories.",
    "call_site_needs_line_evidence": "'Call-site evidence' must cite at least one file and line where an advisory-named symbol is called.",
    "heuristics_never_verified": "Heuristic signals are never 'verified' findings.",
    "provenance_verified_needs_details": "'Verified provenance' must name the repository, commit and transparency-log entry.",
}
REPORT_CHECKS = {
    "scores_bounded_and_explained": "Every score is unknown or within 0-100 and has a factor-by-factor explanation.",
    "evidence_on_every_finding": "Every finding has an ID and at least one evidence entry.",
    "summary_matches_findings": "Summary counts equal the findings actually reported.",
    "policy_decision_reproducible": "Re-evaluating the policy on the final report gives the same verdict.",
}


class _Recorder:
    def __init__(self):
        self.stats = {k: {"checked": 0, "failed": 0} for k in list(CHECKS) + list(REPORT_CHECKS)}
        self.corrections: list[dict] = []

    def check(self, key: str, ok: bool, target: Optional[str] = None, before=None, after=None, reason: str = "",
              finding: Optional[dict] = None):
        self.stats[key]["checked"] += 1
        if ok:
            return
        self.stats[key]["failed"] += 1
        if len(self.corrections) < 300:
            self.corrections.append({"check": key, "target": target, "before": before, "after": after, "reason": reason})
        if finding is not None:
            finding.setdefault("review", {"status": "corrected", "corrections": []})
            finding["review"]["status"] = "corrected"
            finding["review"]["corrections"].append({"check": key, "before": before, "after": after, "reason": reason})
            finding.setdefault("evidence", []).append({"observation": f"Independent reviewer: {reason}", "source": "Independent Security Reviewer",
                                                       "origin": "computed"})


def review_claims(b: Board) -> dict:
    """Pass 1: challenge claims before scoring. Returns the review section (also stored on the board)."""
    pr = b.progress
    pr.start("review")
    rec = _Recorder()
    graph = b.graph

    # ---- vulnerabilities
    for f in b.vuln_findings:
        p = graph.packages.get(f["package_id"])
        adv = f["advisory"]
        if f.get("verified"):
            ok = bool(adv.get("summary") or adv.get("details")) and adv.get("applies_to_installed") is not False \
                 and bool(p and p.version_exact) and any("OSV" in (e.get("source") or "") for e in f.get("evidence", []))
            rec.check("verified_needs_advisory", ok, f["id"], "verified", "unverified",
                      "Downgraded: the 'verified' claim lacked advisory details, an exact version or agreeing range evidence.", f)
            if not ok:
                f["verified"] = False
        reach = f.get("reachability") or {}
        if reach.get("level") == "symbol_call":
            ok = any(e.get("kind") == "call" and e.get("file") and e.get("line") for e in reach.get("evidence", []))
            rec.check("call_site_needs_line_evidence", ok, f["id"], "symbol_call", "imported",
                      "Downgraded: call-site evidence claimed without a cited file and line.", f)
            if not ok:
                reach["level"], reach["label"] = "imported", "Imported by application (reviewer-corrected)"
        f.setdefault("review", {"status": "confirmed", "corrections": []})

    # ---- clean claims
    for pid, info in b.pkg_info.items():
        if info.get("vuln_status") == "checked":
            ok = info.get("osv_origin") in ("live", "cache", "stale", "fixture")
            rec.check("clean_needs_intelligence", ok, pid, "checked", "unverified",
                      "Package was marked checked without any intelligence origin.")
            if not ok:
                info.update(vuln_status="unverified", vuln_status_code="intel_unavailable",
                            vuln_status_reason="Reviewer: no intelligence source recorded for this check.")

    # ---- remediation claims
    plans_by_pkg = {pl["package_id"]: pl for pl in b.plans}
    for pl in b.plans:
        if pl.get("fix_confidence") == "verified":
            chk = {c["version"]: c["known_advisories"] for c in pl.get("candidates_checked") or []}
            ok = pl.get("target") in chk and chk[pl["target"]] == []
            rec.check("fix_verified_needs_osv_recheck", ok, pl["package_id"], "verified", "candidate",
                      f"Downgraded: no OSV re-check showing zero advisories for {pl.get('package')}@{pl.get('target')}.")
            if not ok:
                pl["fix_confidence"] = "candidate"
                if pl["state"] == "safe_candidate":
                    pl["state"] = "requires_review"
        if pl.get("state") == "safe_candidate":
            via_parent = any(c.get("result") == "via parent" for c in pl.get("compatibility", []))
            ok = not pl.get("unfixed_advisories") and not pl.get("remaining_advisories") \
                 and (not pl.get("major_change") or via_parent or not pl.get("direct"))
            rec.check("safe_candidate_needs_compatibility", ok, pl["package_id"], "safe_candidate", "requires_review",
                      f"Downgraded: {pl.get('package')} fix crosses a breaking-change boundary or leaves advisories unfixed.")
            if not ok:
                pl["state"] = "requires_review"
    for f in b.vuln_findings:   # propagate any plan corrections to the findings
        pl = plans_by_pkg.get(f["package_id"])
        if pl and f.get("remediation"):
            if (f["remediation"]["fix_confidence"], f["remediation"]["state"]) != (pl["fix_confidence"], pl["state"]):
                f["remediation"].update(fix_confidence=pl["fix_confidence"], state=pl["state"])
                f.setdefault("review", {"status": "corrected", "corrections": []})["status"] = "corrected"

    # ---- heuristics are never verified
    for s in b.signal_findings:
        ok = not s.get("verified")
        rec.check("heuristics_never_verified", ok, s.get("id"), True, False, "Heuristic signal cannot be a verified finding.", s)
        s["verified"] = False

    # ---- provenance claims
    for pid, v in b.pkg_prov.items():
        if v.get("status") == "verified":
            ok = bool(v.get("repository") and v.get("commit") and v.get("rekor_log_index"))
            rec.check("provenance_verified_needs_details", ok, pid, "verified", "unavailable",
                      "Downgraded: verified provenance without repository, commit and transparency-log entry.")
            if not ok:
                v["status"] = "unavailable"

    conflicts = _conflicts(b)
    review = {
        "pass1": {k: {"description": CHECKS[k], **rec.stats[k]} for k in CHECKS},
        "corrections": rec.corrections,
        "conflicts": conflicts,
        "_recorder": rec,
    }
    b.review = review
    n_fail = sum(s["failed"] for k, s in rec.stats.items() if k in CHECKS)
    pr.done("review", f"{sum(s['checked'] for k, s in rec.stats.items() if k in CHECKS)} claim(s) checked, "
                      f"{n_fail} corrected, {len(conflicts)} conflict(s)")
    b.say(NAME, "orchestrator", f"Claims reviewed: {n_fail} correction(s), {len(conflicts)} conflict(s) flagged.")
    return review


def _conflicts(b: Board) -> list[dict]:
    out = []
    sig_by_pkg: dict[str, list[dict]] = {}
    for s in b.signal_findings:
        if s.get("package_id"):
            sig_by_pkg.setdefault(s["package_id"], []).append(s)
    for pid, v in b.pkg_prov.items():
        sigs = sig_by_pkg.get(pid, [])
        name = b.graph.packages[pid].name if pid in b.graph.packages else pid
        if v.get("status") == "verified":
            if any(s["signal"] == "typosquat" and s["severity"] in ("medium", "high") for s in sigs):
                out.append({"type": "provenance_vs_typosquat", "package_id": pid, "package": name,
                            "detail": f"Build provenance verifies (built from {v.get('repository')}), but the name resembles a popular package.",
                            "suggestion": "Verified provenance proves where it was built, not that it is the package you meant. "
                                          "Confirm the repository is the intended project."})
            if any(s["signal"] in ("integrity_mismatch",) for s in sigs):
                out.append({"type": "provenance_vs_integrity", "package_id": pid, "package": name,
                            "detail": "Provenance verifies against one hash, but the lockfile and registry hashes disagree.",
                            "suggestion": "Regenerate the lockfile from the official registry and rescan; treat as possible tampering until explained."})
    for f in b.vuln_findings:
        if f["advisory"].get("applies_to_installed") is False:
            out.append({"type": "osv_vs_local_range", "package_id": f["package_id"], "package": f["package_id"],
                        "detail": f"OSV reports {f['advisory']['id']} but the local range check places the installed version outside the published range.",
                        "suggestion": "Read the advisory's affected versions; the provider data or the range may be inaccurate."})
    for pl in b.plans:
        bad = [c for c in pl.get("compatibility", []) if c.get("result") == "not verified clean"]
        if bad:
            out.append({"type": "fix_resolves_to_vulnerable_version", "package_id": pl["package_id"], "package": pl["package"],
                        "detail": bad[0]["detail"], "suggestion": "Pick a newer parent release or add an override, then rescan."})
    return out[:100]


def review_report(b: Board, result: dict) -> dict:
    """Pass 2: consistency of the assembled report. Returns the final review section."""
    from .. import policy as policy_mod
    review = b.review
    rec: _Recorder = review.pop("_recorder")
    for f in result["findings"]:
        s = f.get("scores") or {}
        ok = all(s.get(k) is None or 0 <= s[k] <= 100 for k in ("intrinsic", "exposure", "priority")) and bool(s.get("factors"))
        rec.check("scores_bounded_and_explained", ok, f.get("id"), None, None, "Score out of range or without explanation.")
        rec.check("evidence_on_every_finding", bool(f.get("id")) and bool(f.get("evidence")), f.get("id"), None, None,
                  "Finding without ID or evidence.")
    s = result["summary"]
    vulns = [f for f in result["findings"] if f["kind"] == "vulnerability"]
    rec.check("summary_matches_findings", s["vulnerabilities"] == len(vulns)
              and s["verified_vulnerabilities"] == sum(1 for f in vulns if f["verified"]), "summary", None, None,
              "Summary counts disagree with findings.")
    again = policy_mod.evaluate(result, result["policy"]["policy"])
    rec.check("policy_decision_reproducible", again["verdict"] == result["policy"]["verdict"], "policy",
              result["policy"]["verdict"], again["verdict"], "Policy verdict not reproducible.")
    pass2 = {k: {"description": REPORT_CHECKS[k], **rec.stats[k]} for k in REPORT_CHECKS}
    corrected = sum(v["failed"] for v in review["pass1"].values())
    report_failures = sum(v["failed"] for v in pass2.values())
    verdict = "rejected" if report_failures else ("approved_with_corrections" if corrected else "approved")
    final = {"verdict": verdict, "pass1": review["pass1"], "pass2": pass2, "corrections": rec.corrections,
             "conflicts": review["conflicts"],
             "statement": {"approved": "All claims are supported by their evidence; the report is internally consistent.",
                           "approved_with_corrections": f"{corrected} unsupported claim(s) were downgraded before scoring; "
                                                        "the corrected report is internally consistent.",
                           "rejected": "The assembled report failed consistency checks; do not rely on it."}[verdict]}
    b.review = final
    return final
