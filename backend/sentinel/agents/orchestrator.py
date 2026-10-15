"""Agent 1 - Orchestrator.

1. Intake: safe input reading, manifest parsing, dependency graph (the facts every agent shares).
2. Plan: which agents run, in what order, on what inputs; independent agents run in parallel.
3. Run: Vulnerability Intelligence || Package Trust  ->  Reachability  ->  Remediation  ->  Reviewer (claims)
4. Assemble: scores, package profiles, summary and the deterministic policy decision.
5. Reviewer (report consistency) and optional AI explanations (never affect findings or verdict).
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .. import __version__, db, remediation, scoring
from ..intel import IntelContext
from ..models import SEVERITY_ORDER
from ..parsers import COVERAGE, parse_repository
from ..parsers.base import ManifestError, ParseContext
from ..reposource import RepoSource
from . import package_trust, reachability_agent, remediation_agent, reviewer, vuln_intel
from .base import AgentRun, Board, Progress, ScanCancelled

PLAN = [
    {"step": 1, "agents": ["vuln_intel", "package_trust"], "parallel": True, "needs": ["dependency graph"],
     "why": "Independent evidence: advisories vs. package origin and behaviour."},
    {"step": 2, "agents": ["reachability"], "parallel": False, "needs": ["vulnerability findings", "trust signals", "source index"],
     "why": "Paths and exposure are attached to findings from both previous agents."},
    {"step": 3, "agents": ["remediation"], "parallel": False, "needs": ["findings with reachability", "registry metadata"],
     "why": "Fixes are planned only for verified findings, prioritised by exposure."},
    {"step": 4, "agents": ["reviewer"], "parallel": False, "needs": ["all claims"],
     "why": "Unsupported claims are downgraded BEFORE scoring so scores reflect only evidence."},
    {"step": 5, "agents": ["orchestrator"], "parallel": False, "needs": ["reviewed claims"],
     "why": "Scores, report and deterministic policy decision."},
    {"step": 6, "agents": ["reviewer"], "parallel": False, "needs": ["final report"],
     "why": "Report consistency checks; optional AI explanations."},
]


class Orchestrator:
    def __init__(self, src: RepoSource, *, offline: bool = False, progress_cb=None, cancel: Optional[threading.Event] = None,
                 settings: Optional[dict] = None, scan_id: Optional[str] = None, policy: Optional[dict] = None):
        self.settings = settings or db.get_settings()
        self.cancel = cancel or threading.Event()
        self.scan_id, self.policy = scan_id, policy
        ictx = IntelContext(offline=offline, cancel_event=self.cancel,
                            enable_registry=self.settings.get("enable_registry_metadata", True),
                            enable_scorecard=self.settings.get("enable_scorecard", True),
                            enable_epss_kev=self.settings.get("enable_epss_kev", True))
        self.b = Board(src=src, settings=self.settings, offline=offline, cancel=self.cancel, ictx=ictx,
                       progress=Progress(progress_cb, self.cancel))
        self.runs: dict[str, AgentRun] = {}

    # ------------------------------------------------------------------ helpers
    def _run_agent(self, key: str, fn, *args):
        run = self.runs.setdefault(key, AgentRun(key))
        run.status, run.started_at = "running", time.time()
        t0 = time.perf_counter()
        try:
            out = fn(*args)
            run.outputs = out if isinstance(out, dict) else {}
            run.status = "done"
            return out
        except ScanCancelled:
            run.status = "cancelled"
            raise
        except Exception as exc:
            run.status, run.error = "failed", f"{type(exc).__name__}: {str(exc)[:200]}"
            self.b.say("orchestrator", key, f"agent failed: {run.error}")
            raise
        finally:
            run.duration = (run.duration or 0) + (time.perf_counter() - t0)

    # ------------------------------------------------------------------ main
    def run(self) -> dict:
        b, pr = self.b, self.b.progress
        t0 = time.time()
        intake = self.runs.setdefault("orchestrator", AgentRun("orchestrator", status="running", started_at=t0))
        ti = time.perf_counter()
        pr.start("load", f"{b.src.report.files_seen} file(s) indexed")
        pr.done("load")
        pr.start("parse")
        b.pctx = ParseContext(graph=b.graph)
        try:
            parse_repository(b.src, b.pctx, progress=lambda p: pr.sub("parse", 0, 1, f"parsed {p}"))
        except ManifestError as exc:
            b.fatal = str(exc)
        b.outcomes = [o.to_dict() for o in b.pctx.outcomes]
        pr.done("parse", f"{len(b.outcomes)} file outcome(s)")
        pr.start("graph")
        b.depth = b.graph.depth_map()
        pr.done("graph", f"{len(b.graph.packages)} packages, {sum(len(v) for v in b.graph.edges.values())} edges")
        intake.duration = time.perf_counter() - ti
        b.say("orchestrator", "all", f"Plan ready: {len(b.graph.packages)} package(s) in {len(b.graph.roots)} component(s); "
                                     f"Vulnerability Intelligence and Package Trust start in parallel.")

        # Step 1: two independent agents in parallel
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="agent") as pool:
            futs = [pool.submit(self._run_agent, "vuln_intel", vuln_intel.run, b),
                    pool.submit(self._run_agent, "package_trust", package_trust.run, b)]
            for f in futs:
                f.result()   # re-raises cancellation / failure
        # Steps 2-4
        self._run_agent("reachability", reachability_agent.run, b)
        self._run_agent("remediation", remediation_agent.run, b)
        self._run_agent("reviewer", reviewer.review_claims, b)
        # Step 5
        tf = time.perf_counter()
        pr.start("finalize")
        result = self._assemble(t0)
        pr.done("finalize", f"policy {result['policy']['verdict']}")
        intake.duration += time.perf_counter() - tf
        # Step 6
        rv = self._run_agent("reviewer", reviewer.review_report, b, result)
        self.runs["reviewer"].outputs = {"verdict": rv["verdict"], "corrections": len(rv["corrections"]),
                                         "conflicts": len(rv["conflicts"])}
        result["review"] = rv
        from . import assistant
        self._run_agent("assistant", assistant.run, b, result)
        if (result.get("ai") or {}).get("status") == "ok":
            result["privacy"]["data_sent"].append({"provider": "Anthropic Claude (optional AI explanations)",
                                                   "data": result["ai"]["data_sent"], "calls": 1})
        intake.status = "done"
        intake.outputs = {"packages": len(b.graph.packages), "components": len(b.graph.roots),
                          "findings": len(result["findings"]), "policy": result["policy"]["verdict"]}
        result["orchestration"] = {
            "plan": PLAN,
            "agents": [self.runs[k].to_dict() for k in ("orchestrator", "vuln_intel", "package_trust", "reachability",
                                                         "remediation", "reviewer", "assistant") if k in self.runs],
            "messages": b.messages,
            "principle": "Facts come from deterministic agents (parsers, OSV, registries, Sigstore, static analysis). "
                         "The reviewer can only downgrade claims. AI, when enabled, only explains.",
        }
        result["scan"]["finished_at"] = _iso(time.time())
        result["scan"]["duration_seconds"] = round(time.time() - t0, 2)
        result["progress"] = {"stages": pr.stages}
        return result

    def _assemble(self, t0: float) -> dict:
        from ..engine import _iso, _registry_summary, _trust_profile, summarize
        from ..analyzers import reachability
        from .. import policy as policy_mod
        b = self.b
        plan_by_pkg = {pl["package_id"]: pl for pl in b.plans}
        for f in b.vuln_findings:
            p = b.graph.packages[f["package_id"]]
            f["scores"] = scoring.score_vulnerability(f, p.scope, p.version_exact, f["exploitation"]["kev"], f["exploitation"]["epss"],
                                                      plan_by_pkg.get(p.id, {}).get("fix_confidence") == "verified")
        for s in b.signal_findings:
            p = b.graph.packages.get(s.get("package_id")) if s.get("package_id") else None
            s["scores"] = scoring.score_signal(s, p.scope if p else "runtime")
        all_findings = b.vuln_findings + b.signal_findings
        all_findings.sort(key=lambda f: (-(f["scores"]["priority"] or -1), -SEVERITY_ORDER.get(f["severity"], -1)))
        by_pkg: dict[str, list] = {}
        for f in all_findings:
            if f.get("package_id"):
                by_pkg.setdefault(f["package_id"], []).append(f)
        packages_out = {}
        for p in b.graph.packages.values():
            meta, origin, ts = b.pkg_meta.get(p.id, (None, "not_requested", None))
            fs = by_pkg.get(p.id, [])
            d = p.to_dict()
            d.update(b.pkg_info.get(p.id, {}))
            d["depth"] = b.depth.get(p.id)
            d["dependents"] = len(b.graph.redges.get(p.id, ())) - sum(1 for r in b.graph.redges.get(p.id, ()) if r in b.graph.roots)
            d["dependencies"] = len(b.graph.edges.get(p.id, {}))
            d["finding_ids"] = [f["id"] for f in fs]
            d["vulnerability_count"] = sum(1 for f in fs if f["kind"] == "vulnerability")
            d["signal_count"] = sum(1 for f in fs if f["kind"] != "vulnerability")
            d["max_severity"] = max((f["severity"] for f in fs), key=lambda s: SEVERITY_ORDER.get(s, -1), default=None)
            d["risk"] = scoring.package_risk(fs)
            d["provenance"] = b.pkg_prov.get(p.id)
            d["trust"] = _trust_profile(p, meta, origin, ts, b.scorecards.get(p.id), b.pkg_prov.get(p.id))
            d["registry"] = _registry_summary(meta, origin, ts, p)
            d["imported_in"] = [{"file": s.file, "line": s.line, "is_test": s.is_test}
                                for s in reachability.imports_for(b.source_index, p)[:10]]
            packages_out[p.id] = d
        providers = b.ictx.provider_summary()
        unverified = [pid for pid, i in b.pkg_info.items() if i["vuln_status"] == "unverified"]
        status = "complete"
        if b.fatal or not b.graph.packages:
            status = "failed" if not b.graph.packages else "partial"
        elif unverified or any(o["status"] in ("error", "unsupported", "partial") for o in b.outcomes) \
                or any(p["status"] in ("degraded", "failed") for p in providers if p["name"] == "osv"):
            status = "partial"
        result = {
            "schema": "sentinel-sc/scan-result@1",
            "scan": {"id": self.scan_id, "source_name": b.src.name, "engine_version": __version__, "offline": b.offline,
                     "source": getattr(b.src, "origin", None), "started_at": _iso(t0), "finished_at": _iso(time.time()),
                     "duration_seconds": round(time.time() - t0, 2), "status": status, "fatal_error": b.fatal},
            "coverage": {"outcomes": b.outcomes, "input": b.src.report.__dict__, "source_index": b.source_index.to_summary(),
                         "unverified_packages": len(unverified),
                         "intel_unavailable_packages": sum(1 for i in b.pkg_info.values() if i["vuln_status_code"] == "intel_unavailable"),
                         "no_exact_version_packages": sum(1 for i in b.pkg_info.values() if i["vuln_status_code"] == "no_exact_version"),
                         "matrix": COVERAGE},
            "providers": providers,
            "privacy": {"data_sent": [{"provider": p["label"], "data": p["data_sent"], "calls": p["live_calls"]}
                                      for p in providers if p["live_calls"]],
                        "never_sent": "Source code, file contents, environment variables, secrets, file paths, and repository names."},
            "stats": b.graph.stats(),
            "graph": b.graph.to_dict(),
            "packages": packages_out,
            "findings": all_findings,
            "remediation": {"plans": b.plans, "combined_patch": remediation.combined_patch(b.plans, b.src, b.graph)},
        }
        result["summary"] = summarize(result)
        result["policy"] = policy_mod.evaluate(result, self.policy or policy_mod.current_policy())
        return result


def _iso(ts):
    from ..engine import _iso as iso
    return iso(ts)
