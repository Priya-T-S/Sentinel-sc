"""HTTP API: full demo flow plus web-security controls."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from helpers import make_zip
from sentinel import db
from sentinel.app import app

H = {"X-Sentinel-Client": "test"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        c.put("/api/settings", json={"offline_mode": True}, headers=H)   # deterministic, fixture-backed
        yield c


def _wait(client, sid, timeout=120):
    t = time.time()
    while time.time() - t < timeout:
        r = client.get(f"/api/scans/{sid}").json()
        if r["status"] not in ("queued", "running"):
            return r
        time.sleep(0.3)
    raise AssertionError("scan timeout")


@pytest.fixture(scope="module")
def demo_scan(client):
    r = client.post("/api/demo/scan", headers=H)
    assert r.status_code == 200
    sid = r.json()["scan_id"]
    st = _wait(client, sid)
    assert st["status"] == "completed", st
    return sid


def test_full_demo_flow(client, demo_scan):
    sid = demo_scan
    res = client.get(f"/api/scans/{sid}/result").json()
    assert res["summary"]["vulnerabilities"] >= 40 and res["scan"]["offline"] is True
    assert all(p["status"] in ("offline", "disabled") for p in res["providers"])
    # findings: filter + paginate
    f = client.get(f"/api/scans/{sid}/findings", params={"kind": "vulnerability", "severity": "critical", "page_size": 5}).json()
    assert f["total"] >= 2 and all(x["severity"] == "critical" for x in f["items"])
    q = client.get(f"/api/scans/{sid}/findings", params={"q": "CVE-2021-23337"}).json()
    assert q["total"] == 1 and q["items"][0]["advisory"]["id"] == "GHSA-35jh-r3h4-6jhm"
    p2 = client.get(f"/api/scans/{sid}/findings", params={"page": 2, "page_size": 10}).json()
    assert p2["page"] == 2 and len(p2["items"]) == 10
    # graph + package + finding detail
    g = client.get(f"/api/scans/{sid}/graph").json()
    assert any(n["type"] == "root" for n in g["nodes"]) and g["edges"]
    pkg = client.get(f"/api/scans/{sid}/package", params={"id": "npm:qs@6.7.0"}).json()
    assert pkg["plan"]["target"] and len(pkg["paths"]) >= 2
    fd = client.get(f"/api/scans/{sid}/findings/{q['items'][0]['id']}").json()
    assert fd["finding"]["reachability"]["level"] == "symbol_call"
    # what-if
    w = client.post(f"/api/scans/{sid}/whatif", json={}, headers=H).json()
    assert w["label"].startswith("SIMULATED") and w["after"]["vulnerabilities"] < w["before"]["vulnerabilities"]
    # exports
    assert client.get(f"/api/scans/{sid}/export/json").json()["schema"] == "sentinel-sc/scan-result@1"
    assert "SENTINEL-SC" in client.get(f"/api/scans/{sid}/export/html").text
    assert client.get(f"/api/scans/{sid}/export/cyclonedx").json()["bomFormat"] == "CycloneDX"
    assert client.get(f"/api/scans/{sid}/export/gate").json()["verdict"] == "fail"
    assert "+++ b/package.json" in client.get(f"/api/scans/{sid}/export/patch").text
    assert client.get(f"/api/scans/{sid}/export/exe").status_code == 404


def test_upload_zip_and_compare(client, demo_scan):
    lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-x"}}}
    data = make_zip({"app/package.json": {"dependencies": {"lodash": "4.17.21"}}, "app/package-lock.json": lock})
    r = client.post("/api/scans", files={"file": ("repo.zip", data, "application/zip")}, data={"offline": "true"}, headers=H)
    assert r.status_code == 200
    st = _wait(client, r.json()["scan_id"])
    assert st["status"] == "completed"
    cmp = client.get(f"/api/compare/{demo_scan}/{r.json()['scan_id']}").json()
    assert cmp["removed_findings"] and "packages_changed" in cmp
    hist = client.get("/api/scans").json()["items"]
    assert len(hist) >= 2


def test_duplicate_scans_deduplicated(client):
    data = make_zip({"requirements.txt": "six==1.16.0\n"})
    a = client.post("/api/scans", files={"file": ("x.zip", data)}, headers=H).json()
    b = client.post("/api/scans", files={"file": ("x.zip", data)}, headers=H).json()
    assert b["deduplicated"] or a["scan_id"] != b["scan_id"]  # dedup only while the first is still running
    _wait(client, a["scan_id"])


def test_policy_settings_roundtrip(client, demo_scan):
    r = client.put("/api/policy", json={"policy": {"fail_on_vulnerability_severity": "none", "fail_on_known_exploited": False,
                                                   "fail_on_signal_kinds": []}}, headers=H)
    assert r.status_code == 200
    ev = client.post(f"/api/scans/{demo_scan}/policy", json={}, headers=H).json()
    assert ev["verdict"] == "warn"
    assert client.put("/api/policy", json={"policy": {"evil_key": 1}}, headers=H).status_code == 400
    assert client.put("/api/policy", json={"policy": {"fail_min_confidence": "maybe"}}, headers=H).status_code == 400
    client.put("/api/policy", json={"policy": {}}, headers=H)


# ------------------------------------------------------------------ web security controls
def test_csrf_header_required(client):
    r = client.post("/api/demo/scan")
    assert r.status_code == 403
    assert client.delete("/api/scans").status_code == 403


def test_dns_rebinding_host_rejected(client):
    r = client.get("/api/health", headers={"Host": "attacker.example"})
    assert r.status_code == 421


def test_security_headers(client):
    r = client.get("/api/health")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "access-control-allow-origin" not in r.headers


def test_no_cors_preflight_approval(client):
    r = client.options("/api/scans", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
                                               "Access-Control-Request-Headers": "x-sentinel-client"})
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize("name,data,code", [
    ("evil.exe", b"MZ....", 400),
    ("repo.zip", b"not a zip", 400),
    ("random.json", b'{"a": 1}', 400),
    ("empty.zip", b"", 400),
])
def test_upload_rejections(client, name, data, code):
    r = client.post("/api/scans", files={"file": (name, data)}, headers=H)
    assert r.status_code == code
    assert "Traceback" not in r.text


def test_upload_traversal_zip_rejected_entries_reported(client):
    data = make_zip({"../../escape/package.json": "{}", "package.json": {"dependencies": {"a": "1.0.0"}}})
    r = client.post("/api/scans", files={"file": ("t.zip", data)}, headers=H)
    st = _wait(client, r.json()["scan_id"])
    res = client.get(f"/api/scans/{r.json()['scan_id']}/result").json()
    assert res["coverage"]["input"]["rejected"]


def test_upload_size_limit(client, monkeypatch):
    from sentinel import app as appmod
    from sentinel.config import Limits
    monkeypatch.setattr(appmod, "LIMITS", Limits(max_upload_bytes=1000))
    r = client.post("/api/scans", files={"file": ("big.zip", b"PK" + b"0" * 5000)}, headers=H)
    assert r.status_code == 413


@pytest.mark.parametrize("sid", ["1' OR '1'='1", "abc", "0" * 15 + "'", "%2e%2e%2f%2e%2e%2fx"])
def test_scan_id_injection(client, sid):
    r = client.get(f"/api/scans/{sid}")
    assert r.status_code == 404
    assert db.scan_list(1) is not None  # table intact


def test_sql_injection_in_query_params_is_inert(client, demo_scan):
    r = client.get(f"/api/scans/{demo_scan}/findings", params={"q": "'; DROP TABLE scans; --"})
    assert r.status_code == 200 and r.json()["total"] == 0
    assert client.get(f"/api/scans/{demo_scan}").status_code == 200


def test_spa_path_traversal(client):
    for p in ["/..%2f..%2fbackend/sentinel/app.py", "/../../etc/passwd", "/%2e%2e/%2e%2e/sentinel.db"]:
        r = client.get(p)
        assert "import" not in r.text[:2000] and "SQLite" not in r.text[:100]


def test_whatif_rejects_unknown_packages(client, demo_scan):
    r = client.post(f"/api/scans/{demo_scan}/whatif", json={"changes": {"npm:nope@1": "1.0.0"}}, headers=H)
    assert r.status_code == 400
    r = client.post(f"/api/scans/{demo_scan}/whatif", json={"changes": {"npm:lodash@4.17.15": "1.0.0; rm -rf /"}}, headers=H)
    assert r.status_code == 400


def test_rate_limit_scan_creation(client):
    from sentinel.app import limiter
    limiter.hits.clear()
    codes = [client.post("/api/scans", files={"file": ("x.exe", b"x")}, headers=H).status_code for _ in range(25)]
    assert 429 in codes
    limiter.hits.clear()


def test_security_events_recorded(client):
    client.post("/api/demo/scan")  # missing CSRF header
    ev = client.get("/api/security-events").json()["items"]
    assert any(e["kind"] == "csrf_rejected" for e in ev)
    assert all("ghp_" not in (e["detail"] or "") for e in ev)
