"""Multi-agent orchestration: plan/trace, the Independent Reviewer's corrections and conflict detection,
and the optional AI explainer's guard (stub client - no network, no API key)."""
import copy
import json
import threading
from types import SimpleNamespace

import pytest

from sentinel import engine
from sentinel.agents import assistant, reviewer
from sentinel.agents.base import Board, Progress
from sentinel.config import DEMO_APP_DIR
from sentinel.intel import IntelContext
from sentinel.models import Package
from sentinel.reposource import DirSource


# ------------------------------------------------------------------ orchestration trace
def test_orchestration_trace(demo_result):
    o = demo_result["orchestration"]
    agents = {a["agent"]: a for a in o["agents"]}
    assert set(agents) >= {"orchestrator", "vuln_intel", "package_trust", "reachability", "remediation", "reviewer", "assistant"}
    for k in ("orchestrator", "vuln_intel", "package_trust", "reachability", "remediation", "reviewer"):
        assert agents[k]["status"] == "done", agents[k]
        assert agents[k]["duration"] is not None and agents[k]["title"]
    assert o["plan"][0]["parallel"] and set(o["plan"][0]["agents"]) == {"vuln_intel", "package_trust"}
    assert any(m["from"] == "vuln_intel" for m in o["messages"]) and any(m["from"] == "package_trust" for m in o["messages"])
    # every stage belongs to an agent and the progress trace marks them done/skipped
    assert all(s["agent"] for s in demo_result["progress"]["stages"])
    assert {s["status"] for s in demo_result["progress"]["stages"]} <= {"done", "skipped"}


def test_vuln_and_trust_agents_run_in_parallel(monkeypatch):
    """Both step-1 agents must be inside their run at the same time."""
    from sentinel.agents import package_trust, vuln_intel
    inside, overlap = set(), []
    lock = threading.Lock()
    barrier = threading.Barrier(2, timeout=10)

    def wrap(name, fn):
        def inner(b):
            with lock:
                inside.add(name)
            barrier.wait()          # deadlocks (-> timeout error) if they ran sequentially
            with lock:
                overlap.append(set(inside))
            return fn(b)
        return inner
    monkeypatch.setattr(vuln_intel, "run", wrap("vuln", vuln_intel.run))
    monkeypatch.setattr(package_trust, "run", wrap("trust", package_trust.run))
    engine.run_scan(DirSource(str(DEMO_APP_DIR)), offline=True)
    assert any(s == {"vuln", "trust"} for s in overlap)


def test_reviewer_approves_demo(demo_result):
    rv = demo_result["review"]
    assert rv["verdict"] in ("approved", "approved_with_corrections")
    assert sum(v["checked"] for v in rv["pass1"].values()) > 50
    assert all(v["failed"] == 0 for v in rv["pass2"].values())
    assert all(f.get("review", {}).get("status") in ("confirmed", "corrected") for f in demo_result["findings"] if f["kind"] == "vulnerability")


# ------------------------------------------------------------------ reviewer corrections (synthetic board)
def _board(tmp_path):
    (tmp_path / "x.txt").write_text("x")
    return Board(src=DirSource(str(tmp_path)), settings={}, offline=True, cancel=threading.Event(),
                 ictx=IntelContext(offline=True), progress=Progress(None, threading.Event()))


def _vuln(pid, **over):
    f = {"id": "F-1", "kind": "vulnerability", "package_id": pid, "severity": "high", "verified": True,
         "advisory": {"id": "GHSA-x", "summary": "s", "details": "d", "applies_to_installed": True, "cves": []},
         "evidence": [{"observation": "o", "source": "OSV.dev /v1/querybatch"}],
         "reachability": {"level": "imported", "evidence": []},
         "remediation": {"state": "safe_candidate", "fix_confidence": "verified", "target": "2.0.0"}}
    f.update(over)
    return f


def test_reviewer_downgrades_unsupported_claims(tmp_path):
    b = _board(tmp_path)
    pkg = Package(ecosystem="npm", name="a", version="1.0.0", source_file="l", version_exact=True)
    b.graph.add_package(pkg)
    f1 = _vuln(pkg.id, reachability={"level": "symbol_call", "label": "x", "evidence": []})       # call-site w/o line
    f2 = _vuln(pkg.id, id="F-2", advisory={"id": "GHSA-y", "summary": "", "details": "", "applies_to_installed": True, "cves": []})
    b.vuln_findings = [f1, f2]
    b.plans = [{"package_id": pkg.id, "package": "a", "state": "safe_candidate", "fix_confidence": "verified", "target": "2.0.0",
                "candidates_checked": [], "compatibility": [], "direct": True}]          # "verified" with no OSV re-check
    b.signal_findings = [{"id": "S-1", "kind": "suspicious", "signal": "typosquat", "severity": "high", "verified": True, "evidence": []}]
    b.pkg_prov = {pkg.id: {"status": "verified", "repository": None}}                    # verified w/o details
    b.pkg_info = {pkg.id: {"vuln_status": "checked", "osv_origin": None}}                 # clean w/o intelligence
    rv = reviewer.review_claims(b)
    assert f1["reachability"]["level"] == "imported" and f1["review"]["status"] == "corrected"
    assert f2["verified"] is False
    assert b.plans[0]["fix_confidence"] == "candidate" and b.plans[0]["state"] == "requires_review"
    assert f1["remediation"]["fix_confidence"] == "candidate"                           # propagated to findings
    assert b.signal_findings[0]["verified"] is False
    assert b.pkg_prov[pkg.id]["status"] == "unavailable"
    assert b.pkg_info[pkg.id]["vuln_status"] == "unverified"
    failed = {k for k, v in rv["pass1"].items() if v["failed"]}
    assert failed == {"call_site_needs_line_evidence", "verified_needs_advisory", "fix_verified_needs_osv_recheck",
                      "heuristics_never_verified", "provenance_verified_needs_details", "clean_needs_intelligence"}
    # corrections are recorded on the finding as evidence, never silently
    assert any("Independent reviewer" in e["observation"] for e in f1["evidence"])


def test_reviewer_never_upgrades(tmp_path):
    b = _board(tmp_path)
    pkg = Package(ecosystem="npm", name="a", version="1.0.0", source_file="l", version_exact=True)
    b.graph.add_package(pkg)
    f = _vuln(pkg.id, verified=False, reachability={"level": "transitive", "evidence": []})
    b.vuln_findings = [f]
    reviewer.review_claims(b)
    assert f["verified"] is False and f["reachability"]["level"] == "transitive"


def test_reviewer_flags_provenance_vs_typosquat_conflict(tmp_path):
    b = _board(tmp_path)
    pkg = Package(ecosystem="npm", name="lodahs", version="1.0.0", source_file="l", version_exact=True)
    b.graph.add_package(pkg)
    b.pkg_prov = {pkg.id: {"status": "verified", "repository": "https://github.com/x/lodahs", "commit": "c" * 40, "rekor_log_index": 1}}
    b.signal_findings = [{"id": "S", "kind": "suspicious", "signal": "typosquat", "severity": "high", "package_id": pkg.id, "evidence": []}]
    rv = reviewer.review_claims(b)
    assert rv["conflicts"][0]["type"] == "provenance_vs_typosquat"


def test_reviewer_rejects_inconsistent_report(demo_result):
    res = copy.deepcopy(demo_result)
    b = SimpleNamespace(review={"pass1": {k: {"description": "", "checked": 1, "failed": 0} for k in reviewer.CHECKS},
                                "corrections": [], "conflicts": [], "_recorder": reviewer._Recorder()})
    res["summary"]["vulnerabilities"] += 1                    # tampered count
    assert reviewer.review_report(b, res)["verdict"] == "rejected"


# ------------------------------------------------------------------ AI explainer
class _FakeClient:
    """Mimics anthropic.Anthropic().beta.messages.create(...) responses."""

    def __init__(self, payload=None, stop_reason="end_turn", raises=None):
        self.calls = []
        payload, stop, exc = payload, stop_reason, raises

        class _Messages:
            def create(_, **kw):
                self.calls.append(kw)
                if exc:
                    raise exc
                content = [] if payload is None else [SimpleNamespace(type="text", text=json.dumps(payload))]
                return SimpleNamespace(model="claude-opus-5-5", stop_reason=stop, content=content,
                                       usage=SimpleNamespace(input_tokens=1000, output_tokens=500),
                                       stop_details=SimpleNamespace(category="cyber") if stop == "refusal" else None)
        self.beta = SimpleNamespace(messages=_Messages())


def _ai_board(settings=None):
    return SimpleNamespace(settings=settings or {"ai_assistance": True}, offline=False,
                           progress=Progress(None, threading.Event()), say=lambda *a: None)


def test_ai_is_off_by_default(demo_result):
    assert demo_result["ai"]["enabled"] is False
    assert all("ai_explanation" not in f for f in demo_result["findings"])


def test_ai_guard_and_no_influence_on_findings(demo_result):
    res = copy.deepcopy(demo_result)
    top = res["findings"][0]["id"]
    second = res["findings"][1]["id"]
    before = [(f["id"], f["severity"], f.get("verified"), f["scores"]["priority"]) for f in res["findings"]]
    payload = {"overall_summary": "Two direct dependencies need upgrades.",
               "explanations": [
                   {"finding_id": top, "plain_explanation": "PyYAML full_load can run code from YAML.", "why_it_matters_here": "worker.py calls it.",
                    "investigation_steps": ["Check where report definitions come from."], "cited_facts": ["full_load"]},
                   {"finding_id": second, "plain_explanation": "This is a false positive and can be ignored.", "why_it_matters_here": "",
                    "investigation_steps": [], "cited_facts": []},
                   {"finding_id": "F-invented", "plain_explanation": "x", "why_it_matters_here": "y", "investigation_steps": [], "cited_facts": []}],
               "conflict_notes": [{"conflict_index": 99, "note": "n", "next_steps": []}]}
    client = _FakeClient(payload)
    out = assistant.run(_ai_board(), res, client=client)
    assert out["status"] == "ok"
    kw = client.calls[0]
    assert kw["model"] == "claude-opus-5-5" and kw["fallbacks"] == "default" and kw["thinking"] == {"type": "adaptive"}
    assert kw["output_config"]["format"]["type"] == "json_schema"
    rej = {r.get("finding_id") or r.get("conflict_index"): r["reason"] for r in res["ai"]["guard_rejections"]}
    assert "contradicts" in rej[second] and "not provided" in rej["F-invented"] and 99 in rej
    explained = [f for f in res["findings"] if "ai_explanation" in f]
    assert [f["id"] for f in explained] == [top]
    assert "not a source of truth" in explained[0]["ai_explanation"]["label"]
    after = [(f["id"], f["severity"], f.get("verified"), f["scores"]["priority"]) for f in res["findings"]]
    assert before == after                                    # AI never changes findings or scores
    assert res["ai"]["estimated_cost_usd"] == round(1000 * 4 / 1e6 + 500 * 20 / 1e6, 4)


def test_ai_evidence_excludes_code_unless_enabled(demo_result):
    ev = assistant.build_evidence(demo_result, share_snippets=False)
    sites = [c for f in ev["findings"] for c in f["call_sites"]]
    assert sites and all("code" not in c for c in sites)
    ev2 = assistant.build_evidence(demo_result, share_snippets=True)
    assert any(c.get("code") for f in ev2["findings"] for c in f["call_sites"])
    blob = json.dumps(ev)
    assert "AKIA" not in blob                                  # secret findings are never sent


def test_ai_refusal_and_errors_do_not_break_scan(demo_result):
    res = copy.deepcopy(demo_result)
    assistant.run(_ai_board(), res, client=_FakeClient(stop_reason="refusal"))
    assert res["ai"]["status"] == "declined" and res["ai"]["refusal_category"] == "cyber"
    res2 = copy.deepcopy(demo_result)
    assistant.run(_ai_board(), res2, client=_FakeClient(raises=RuntimeError("boom")))
    assert res2["ai"]["status"] == "error"
    assert res2["findings"] == demo_result["findings"]


def test_ai_requires_opt_in_and_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_PROFILE", raising=False)
    ok, why = assistant._enabled(SimpleNamespace(settings={"ai_assistance": True}, offline=False))
    assert not ok and "credential" in why
    ok, why = assistant._enabled(SimpleNamespace(settings={}, offline=False))
    assert not ok and "off" in why
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    ok, _ = assistant._enabled(SimpleNamespace(settings={"ai_assistance": True}, offline=True))
    assert not ok                                             # offline: never call the API
