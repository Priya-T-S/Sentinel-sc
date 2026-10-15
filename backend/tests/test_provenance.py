"""Sigstore verification of npm build provenance. Uses the real express@4.22.3 attestation from the
versioned fixture (no network) and tampered copies of it."""
import base64
import copy
import json

import pytest

from sentinel import db, provenance as prov
from sentinel.intel import IntelContext
from sentinel.models import Package

NAME, VERSION = "express", "4.22.3"


@pytest.fixture(scope="module")
def real():
    hit = db.cache_get(f"npm:att:{NAME}@{VERSION}", None)
    assert hit, "fixture must contain the express attestation"
    lock = json.loads((__import__("sentinel.config", fromlist=["DEMO_DIR"]).DEMO_DIR / "pr-review" / "base" / "package-lock.json").read_text())
    integrity = lock["packages"]["node_modules/express"]["integrity"]
    return hit[0], integrity


def _pkg(integrity):
    return Package(ecosystem="npm", name=NAME, version=VERSION, source_file="package-lock.json", version_exact=True,
                   integrity=integrity, resolved=f"https://registry.npmjs.org/express/-/express-{VERSION}.tgz")


def _with_attestation(monkeypatch, data):
    monkeypatch.setattr(prov, "fetch_attestations", lambda ictx, n, v: (data, "fixture"))


META = {"repository": "https://github.com/expressjs/express", "versions": {}}


def test_real_attestation_verifies(real):
    _, integrity = real
    v = prov.verify_package(IntelContext(offline=True), _pkg(integrity), META)
    assert v["status"] == "verified", v
    assert v["repository"] == "https://github.com/expressjs/express"
    assert v["commit"] == "899b52494e74327905c16164decdc6e51f803af8"
    assert v["digest_source"] == "lockfile" and v["rekor_log_index"]


def test_artifact_hash_mismatch_is_invalid(real):
    _, integrity = real
    other = "sha512-" + base64.b64encode(b"\x01" * 64).decode()
    v = prov.verify_package(IntelContext(offline=True), _pkg(other), META)
    assert v["status"] == "invalid" and "does not match" in v["reason"]
    f = prov.to_finding(_pkg(other), v)
    assert f["signal"] == "provenance_invalid" and f["severity"] == "high"


def test_tampered_statement_is_invalid(real, monkeypatch):
    data, integrity = real
    bad = copy.deepcopy(data)
    att = next(a for a in bad["attestations"] if a["predicateType"] == prov.SLSA_V1)
    st = json.loads(base64.b64decode(att["bundle"]["dsseEnvelope"]["payload"]))
    st["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "f" * 40
    att["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    _with_attestation(monkeypatch, bad)
    v = prov.verify_package(IntelContext(offline=True), _pkg(integrity), META)
    assert v["status"] == "invalid" and "Sigstore verification failed" in v["reason"]


def test_claimed_repository_must_match_certificate(real, monkeypatch):
    data, integrity = real
    bad = copy.deepcopy(data)
    att = next(a for a in bad["attestations"] if a["predicateType"] == prov.SLSA_V1)
    st = json.loads(base64.b64decode(att["bundle"]["dsseEnvelope"]["payload"]))
    st["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"] = "https://github.com/attacker/express"
    att["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    _with_attestation(monkeypatch, bad)
    v = prov.verify_package(IntelContext(offline=True), _pkg(integrity), META)
    assert v["status"] == "invalid"


def test_repository_mismatch_with_registry(real):
    _, integrity = real
    v = prov.verify_package(IntelContext(offline=True), _pkg(integrity), {"repository": "https://github.com/someone-else/express"})
    assert v["status"] == "repo_mismatch"
    assert prov.to_finding(_pkg(integrity), v)["signal"] == "provenance_repo_mismatch"


def test_absent_and_malformed(real, monkeypatch):
    _, integrity = real
    _with_attestation(monkeypatch, {"attestations": []})
    assert prov.verify_package(IntelContext(offline=True), _pkg(integrity), META)["status"] == "absent"
    _with_attestation(monkeypatch, {"attestations": [{"predicateType": prov.SLSA_V1, "bundle": {"dsseEnvelope": {"payload": "!!!"}}}]})
    assert prov.verify_package(IntelContext(offline=True), _pkg(integrity), META)["status"] == "invalid"
    _with_attestation(monkeypatch, None)
    assert prov.verify_package(IntelContext(offline=True), _pkg(integrity), META)["status"] == "unavailable"


def test_engine_reports_verified_provenance_offline():
    from sentinel import engine
    from sentinel.config import DEMO_DIR
    from sentinel.reposource import DirSource
    res = engine.run_scan(DirSource(str(DEMO_DIR / "pr-review" / "base")), offline=True)
    assert res["summary"]["provenance"]["verified"] >= 3
    ex = res["packages"]["npm:express@4.22.3"]
    assert ex["provenance"]["status"] == "verified"
    item = next(t for t in ex["trust"]["items"] if t["key"] == "provenance")
    assert item["status"] == "verified"
    lodash = res["packages"]["npm:lodash@4.18.1"]
    assert lodash["provenance"]["status"] == "absent"
