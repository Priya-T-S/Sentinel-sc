"""End-to-end engine behaviour on the demo project (fixture-backed, offline, deterministic)."""
import json

from sentinel import engine, policy, sbom
from sentinel.config import FIXTURE_DIR
from sentinel.reposource import SingleFileSource

EXPECTED = json.loads((FIXTURE_DIR / "expected-findings.json").read_text())


def _vulns(res):
    return [f for f in res["findings"] if f["kind"] == "vulnerability"]


def _pkg(res, name):
    return next(p for p in res["packages"].values() if p["name"] == name)


def test_expected_vulnerabilities_found(demo_result):
    got = {(demo_result["packages"][f["package_id"]]["name"], demo_result["packages"][f["package_id"]]["version"], f["advisory"]["id"])
           for f in _vulns(demo_result)}
    want = {(v["package"], v["version"], v["advisory"]) for v in EXPECTED["vulnerabilities"]}
    assert want <= got
    # real advisories referenced
    ids = {f["advisory"]["id"] for f in _vulns(demo_result)}
    assert {"GHSA-35jh-r3h4-6jhm", "GHSA-hrpp-h998-j3pp", "GHSA-8q59-q68h-6hv4"} <= ids


def test_non_vulnerable_control_is_clean(demo_result):
    d = _pkg(demo_result, "dayjs")
    assert d["vuln_status"] == "checked" and d["vulnerability_count"] == 0


def test_direct_and_transitive_paths(demo_result):
    qs = next(f for f in _vulns(demo_result) if f["advisory"]["id"] == "GHSA-hrpp-h998-j3pp")
    names = [[demo_result["packages"].get(n, {}).get("name", "ROOT") for n in p] for p in qs["paths"]]
    assert ["ROOT", "express", "qs"] in names
    assert ["ROOT", "express", "body-parser", "qs"] in names
    assert not _pkg(demo_result, "qs")["direct"] and _pkg(demo_result, "lodash")["direct"]
    assert qs["reachability"]["level"] == "transitive_imported"


def test_alias_dedup_one_flaw_one_finding(demo_result):
    lodash = [f for f in _vulns(demo_result) if demo_result["packages"][f["package_id"]]["name"] == "lodash"]
    all_ids = [i for f in lodash for i in f["advisory"]["ids"]]
    assert len(all_ids) == len(set(all_ids))           # no advisory ID counted twice
    merged = next(f for f in lodash if "GHSA-35jh-r3h4-6jhm" in f["advisory"]["ids"])
    assert "GHSA-r5fr-rjxr-66jc" in merged["advisory"]["ids"]   # aliased record merged


def test_static_call_site_evidence(demo_result):
    tmpl = next(f for f in _vulns(demo_result) if f["advisory"]["id"] == "GHSA-35jh-r3h4-6jhm")
    assert tmpl["reachability"]["level"] == "symbol_call"
    calls = [e for e in tmpl["reachability"]["evidence"] if e.get("kind") == "call"]
    assert calls[0]["file"] == "src/server.js" and calls[0]["symbol"] == "template"
    yml = next(f for f in _vulns(demo_result) if f["advisory"]["id"] == "GHSA-8q59-q68h-6hv4")
    assert yml["reachability"]["level"] == "symbol_call"
    # requests is imported but no affected symbol is called: must NOT be upgraded to symbol_call
    req = [f for f in _vulns(demo_result) if demo_result["packages"][f["package_id"]]["name"] == "requests"]
    assert all(f["reachability"]["level"] == "imported" for f in req)
    # dev dependency never imported
    mm = next(f for f in _vulns(demo_result) if demo_result["packages"][f["package_id"]]["name"] == "minimist")
    assert mm["reachability"]["level"] == "declared_not_imported"


def test_scores_are_explained_and_bounded(demo_result):
    for f in demo_result["findings"]:
        s = f["scores"]
        assert s["factors"], f["id"]
        for k in ("intrinsic", "exposure", "priority"):
            assert s[k] is None or 0 <= s[k] <= 100
    mm = next(f for f in _vulns(demo_result) if demo_result["packages"][f["package_id"]]["name"] == "minimist")
    assert mm["severity"] == "critical" and mm["scores"]["priority_bucket"] in ("P3", "P4")  # dev + not imported


def test_suspicious_signals_are_labelled_heuristic(demo_result):
    sig = [f for f in demo_result["findings"] if f.get("package_id", "").startswith("npm:lodahs")]
    kinds = {f["signal"] for f in sig}
    assert {"typosquat", "install_script", "source_patterns"} <= kinds
    assert all(not f["verified"] for f in sig)
    sp = next(f for f in sig if f["signal"] == "source_patterns")
    decoded = [e.get("decoded_preview") for e in sp["evidence"] if e.get("decoded_preview")]
    assert decoded == ['console.log("demo")']
    # established look-alike is not escalated
    sb = [f for f in demo_result["findings"] if f.get("signal") == "typosquat" and "safer-buffer" in f["package_id"]]
    assert all(f["severity"] == "info" for f in sb)


def test_remediation_verified_and_grounded(demo_result):
    plans = {p["package"]: p for p in demo_result["remediation"]["plans"]}
    assert plans["lodash"]["fix_confidence"] == "verified"
    for p in plans.values():
        if p["fix_confidence"] == "verified":
            chosen = [c for c in p["candidates_checked"] if c["version"] == p["target"]]
            assert chosen and chosen[0]["known_advisories"] == []
    qs = plans["qs"]
    assert any(c["result"].startswith("resolves fix") for c in qs["compatibility"])
    patch = demo_result["remediation"]["combined_patch"]["files"][0]
    assert patch["file"] == "package.json" and patch["applied"] is False
    assert '+    "express": "4.22.3"' in patch["diff"]


def test_whatif_is_labelled_and_reduces_risk(demo_result):
    w = engine.whatif(demo_result, offline=True)
    assert w["label"].startswith("SIMULATED")
    assert w["after"]["vulnerabilities"] < w["before"]["vulnerabilities"]
    assert w["limitations"]


def test_policy_gate_deterministic(demo_result):
    a = policy.evaluate(demo_result, policy.DEFAULT_POLICY)
    b = policy.evaluate(demo_result, policy.DEFAULT_POLICY)
    assert a == b and a["verdict"] == "fail" and a["exit_code"] == 1
    lenient = dict(policy.DEFAULT_POLICY, fail_on_vulnerability_severity="none", fail_on_known_exploited=False, fail_on_signal_kinds=[])
    assert policy.evaluate(demo_result, lenient)["verdict"] == "warn"
    ignore = dict(policy.DEFAULT_POLICY, fail_on_signal_kinds=[], ignored_advisories=["GHSA-8q59-q68h-6hv4", "GHSA-xvch-5gv4-984h", "CVE-2020-14343"])
    v = policy.evaluate(demo_result, ignore)
    assert all(x.get("advisory") not in ("GHSA-8q59-q68h-6hv4",) for x in v["violations"])


def test_sbom_export(demo_result):
    bom = sbom.export_cyclonedx(demo_result)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    purls = {c.get("purl") for c in bom["components"]}
    assert "pkg:npm/lodash@4.17.15" in purls
    assert all(v["analysis"]["state"] in ("in_triage", "not_affected") for v in bom["vulnerabilities"])
    lodash = next(c for c in bom["components"] if c.get("purl") == "pkg:npm/lodash@4.17.15")
    assert lodash["hashes"][0]["alg"] == "SHA-512" and len(lodash["hashes"][0]["content"]) == 128


def test_sbom_roundtrip_import(demo_result):
    bom = sbom.export_cyclonedx(demo_result)
    res = engine.run_scan(SingleFileSource("bom.json", json.dumps(bom).encode()), offline=True)
    got = {(p["name"], p["version"]) for p in res["packages"].values()}
    assert ("lodash", "4.17.15") in got and ("qs", "6.7.0") in got
    qs = next(f for f in res["findings"] if f["kind"] == "vulnerability" and f["advisory"]["id"] == "GHSA-hrpp-h998-j3pp")
    assert qs["reachability"]["level"] == "unknown"  # no source in an SBOM: never claimed reachable


def test_no_false_clean_when_intelligence_unavailable(tmp_path):
    from sentinel import db
    previous = db._db_path
    db.init(tmp_path / "empty.db")  # no cache, no fixture
    try:
        lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "4.17.15"}},
                "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz", "integrity": "sha512-x"}}}
        res = engine.run_scan(SingleFileSource("package-lock.json", json.dumps(lock).encode()), offline=True)
        p = res["packages"]["npm:lodash@4.17.15"]
        assert p["vuln_status"] == "unverified" and p["vuln_status_code"] == "intel_unavailable"
        assert res["scan"]["status"] == "partial"
        assert res["policy"]["verdict"] == "fail"   # never passes the gate as "clean"
    finally:
        db.init(previous)
