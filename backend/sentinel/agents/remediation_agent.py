"""Agent 5 - Remediation (deterministic).

For each vulnerable package: smallest version fixing every advisory, re-verified against OSV, checked
against declared and parent ranges (resolved through registry ranges for transitive packages), with an
in-memory patch candidate. Nothing is applied to the repository.
"""
from __future__ import annotations

from .. import remediation, scoring
from ..models import SEVERITY_ORDER
from .base import Board

NAME = "remediation"


def run(b: Board) -> dict:
    pr = b.progress
    pr.start("remediation")
    by_pkg: dict[str, list[dict]] = {}
    for f in b.vuln_findings:
        by_pkg.setdefault(f["package_id"], []).append(f)
    plans = []
    ordered = sorted(by_pkg.items(), key=lambda kv: -max(SEVERITY_ORDER.get(f["severity"], 0) for f in kv[1]))
    for i, (pid, fs) in enumerate(ordered):
        p = b.graph.packages[pid]
        reach = max((f["reachability"]["level"] for f in fs), key=lambda lvl: scoring.REACH_W.get(lvl, 0))
        plan = remediation.plan_package(b.ictx, b.graph, p, fs, b.src, b.meta_cache, reach)
        plans.append(plan)
        for f in fs:
            f["remediation"] = {"state": plan["state"], "target": plan.get("target"), "fix_confidence": plan["fix_confidence"],
                                "major_change": plan.get("major_change"), "plan_package": pid}
        pr.sub("remediation", i + 1, len(ordered), f"{i + 1}/{len(ordered)} packages planned")
    b.plans = plans
    verified = sum(1 for pl in plans if pl.get("fix_confidence") == "verified")
    pr.done("remediation", f"{len(plans)} plan(s), {verified} fix(es) verified on OSV")
    b.say(NAME, "reviewer", f"{len(plans)} remediation plan(s) proposed; {verified} claim an OSV-verified fix - please check.")
    return {"plans": len(plans), "fix_verified": verified,
            "states": {s: sum(1 for pl in plans if pl["state"] == s) for s in {pl["state"] for pl in plans}}}
