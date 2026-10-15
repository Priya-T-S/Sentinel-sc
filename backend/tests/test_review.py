"""Pull-request dependency review (offline, fixture-backed demo base vs head)."""
import copy

import pytest

from sentinel import engine, review
from sentinel.config import DEMO_DIR
from sentinel.reposource import DirSource


@pytest.fixture(scope="module")
def pr_scans():
    base = engine.run_scan(DirSource(str(DEMO_DIR / "pr-review" / "base")), offline=True)
    head = engine.run_scan(DirSource(str(DEMO_DIR / "pr-review" / "head")), offline=True)
    return base, head


def test_review_flags_what_the_pr_introduces(pr_scans):
    base, head = pr_scans
    rv = review.review(base, head)
    added = {a["name"] for a in rv["packages"]["added"]}
    assert {"axios", "lodahs"} <= added
    assert any(c["name"] == "lodash" and c["direction"] == "downgrade" for c in rv["packages"]["changed"])
    types = {a["type"] for a in rv["attention"]}
    assert {"install_script", "non_registry_source", "downgrade", "typosquat"} <= types
    new_ids = {f["advisory"] for f in rv["new_findings"] if f["kind"] == "vulnerability"}
    assert "GHSA-35jh-r3h4-6jhm" in new_ids            # re-introduced by the lodash downgrade
    assert rv["gate"]["verdict"] == "fail"
    rules = {v["rule"] for v in rv["gate"]["violations"]}
    assert {"fail_on_vulnerability_severity", "fail_on_signal_kinds"} <= rules


def test_unchanged_pr_passes(pr_scans):
    base, _ = pr_scans
    rv = review.review(base, base)
    assert rv["gate"]["verdict"] == "pass"
    assert rv["summary"] == {**rv["summary"], "added": 0, "changed": 0, "new_vulnerabilities": 0, "new_signals": 0}


def test_removing_risk_resolves_and_passes(pr_scans):
    base, head = pr_scans
    rv = review.review(head, base)    # the reverse "PR" removes axios + typosquat and upgrades lodash
    assert rv["summary"]["resolved"] > 0
    assert rv["gate"]["verdict"] == "pass"
    assert any(c["direction"] == "upgrade" for c in rv["packages"]["changed"])


def test_pre_existing_debt_does_not_block_a_pr(pr_scans):
    _, head = pr_scans
    rv = review.review(head, head)   # head already has critical issues, but this "PR" adds nothing
    assert rv["gate"]["verdict"] == "pass"


def test_custom_policy_overrides_review_default(pr_scans):
    base, head = pr_scans
    from sentinel.policy import DEFAULT_POLICY
    lenient = dict(DEFAULT_POLICY, fail_on_vulnerability_severity="none", fail_on_signal_kinds=[], fail_on_known_exploited=False)
    rv = review.review(base, head, lenient)
    assert rv["gate"]["verdict"] == "warn"   # still warns: attention items exist


def test_markdown_is_safe_and_compact(pr_scans):
    base, head = pr_scans
    evil = copy.deepcopy(head)
    pid = next(k for k, p in evil["packages"].items() if p["name"] == "axios")
    evil["packages"][pid]["name"] = '<img src=x onerror=alert(1)>](javascript:alert(1))'
    for f in evil["findings"]:
        if f.get("package_id") == pid:
            f["title"] = "<script>alert(1)</script> | broken | table"
            f["advisory"]["source_url"] = "javascript:alert(1)"
    md = review.to_markdown(review.review(base, evil))
    assert md.startswith(review.MARKER)
    import re
    # every '<' / ']' coming from attacker data is backslash-escaped, so GitHub renders it as text
    assert not re.search(r"(?<!\\)<(img|script)", md)
    assert not re.search(r"(?<!\\)\]\(javascript:", md)
    assert "\\|" in md                                      # table pipes neutralised
    assert md.count("\n") < 250                              # grouped, not one row per advisory


def test_review_api(monkeypatch):
    import time
    from fastapi.testclient import TestClient
    from sentinel import app as appmod
    from sentinel.reposource import DirSource as DS
    with TestClient(appmod.app) as c:
        h = {"X-Sentinel-Client": "test"}
        c.put("/api/settings", json={"offline_mode": True}, headers=h)
        ids = []
        for sub in ("base", "head"):
            sid, _ = appmod.jobs.submit(lambda *_ , s=sub: DS(str(DEMO_DIR / "pr-review" / s)), source_name=f"pr-{sub}",
                                        source_kind="test", content_key=f"pr-{sub}-{time.time()}".encode(), offline=True)
            ids.append(sid)
        for sid in ids:
            for _ in range(300):
                if c.get(f"/api/scans/{sid}").json()["status"] not in ("queued", "running"):
                    break
                time.sleep(0.1)
        rv = c.get(f"/api/compare/{ids[0]}/{ids[1]}/review").json()
        assert rv["gate"]["verdict"] == "fail" and rv["markdown"].startswith(review.MARKER)
        md = c.get(f"/api/compare/{ids[0]}/{ids[1]}/review", params={"format": "markdown"})
        assert md.status_code == 200 and "dependency review" in md.text
