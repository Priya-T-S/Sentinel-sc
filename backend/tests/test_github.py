"""Scan-from-GitHub-URL: strict URL parsing and safe archive download (mocked GitHub; no real network)."""
import httpx
import pytest

from helpers import make_zip
from sentinel import github as G
from sentinel.intel import http as H

SHA = "a" * 40


@pytest.mark.parametrize("text,expected", [
    ("https://github.com/expressjs/express", ("expressjs", "express", None)),
    ("github.com/expressjs/express.git", ("expressjs", "express", None)),
    ("http://www.github.com/expressjs/express/", ("expressjs", "express", None)),
    ("expressjs/express", ("expressjs", "express", None)),
    ("expressjs/express@4.17.1", ("expressjs", "express", "4.17.1")),
    ("https://github.com/o/r/tree/feature/x-1", ("o", "r", "feature/x-1")),
    (f"https://github.com/o/r/commit/{SHA}", ("o", "r", SHA)),
    ("https://github.com/o/r/releases/tag/v1.2.3", ("o", "r", "v1.2.3")),
    ("https://github.com/o/r/issues/5", ("o", "r", None)),
    ("https://github.com/o/r?tab=readme#top", ("o", "r", None)),
])
def test_parse_valid(text, expected):
    r = G.parse_github_url(text)
    assert (r.owner, r.repo, r.ref) == expected


@pytest.mark.parametrize("text", [
    "", "   ", "https://gitlab.com/o/r", "https://github.com.evil.com/o/r", "https://evil.com/github.com/o/r",
    "https://user:pw@github.com/o/r", "https://github.com:8443/o/r", "ftp://github.com/o/r", "file:///etc/passwd",
    "https://github.com/onlyowner", "https://github.com/-bad/r", "https://github.com/o/..", "https://169.254.169.254/o/r",
    "git@github.com:o/r.git", "o/r@../../etc", "o/r@-x", "https://github.com/o/r/tree/a..b", "o/r @main", "o/r$(id)",
])
def test_parse_rejects(text):
    with pytest.raises(G.GitHubImportError):
        G.parse_github_url(text)


def _mock(monkeypatch, handler):
    monkeypatch.setattr(H, "_client", httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))


@pytest.fixture(autouse=True)
def _reset_client(monkeypatch):
    yield
    monkeypatch.setattr(H, "_client", None)


def _github(archive: bytes, *, private=False, exists=True, status=200, archive_redirect=None):
    def handler(request: httpx.Request):
        host, path = request.url.host, request.url.path
        if host == "api.github.com" and path == "/repos/acme/app":
            if status != 200:
                return httpx.Response(status)
            return httpx.Response(200, json={"default_branch": "main", "private": private, "size": 10}) if exists else httpx.Response(404)
        if host == "api.github.com" and path.startswith("/repos/acme/app/commits/"):
            return httpx.Response(200, json={"sha": SHA, "commit": {"committer": {"date": "2026-10-01T00:00:00Z"}}})
        if host == "codeload.github.com" and path == f"/acme/app/zip/{SHA}":
            if archive_redirect:
                return httpx.Response(302, headers={"location": archive_redirect})
            return httpx.Response(200, content=archive)
        return httpx.Response(404)
    return handler


def test_fetch_resolves_commit_and_records_provenance(monkeypatch):
    zipped = make_zip({"app-main/package.json": {"dependencies": {"a": "1.0.0"}}})
    _mock(monkeypatch, _github(zipped))
    steps = []
    src, meta = G.fetch_repository(G.parse_github_url("https://github.com/acme/app"), steps.append)
    assert meta["commit"] == SHA and meta["resolved_ref"] == "main" and meta["repository"] == "acme/app"
    assert src.list_files() == ["package.json"]          # GitHub's wrapper folder stripped
    assert src.origin["commit_url"].endswith(SHA)
    assert any("exact commit" in s for s in steps)


def test_missing_or_private_repo(monkeypatch):
    _mock(monkeypatch, _github(b"", exists=False))
    with pytest.raises(G.GitHubImportError, match="not found, or it is private"):
        G.fetch_repository(G.parse_github_url("acme/app"))
    _mock(monkeypatch, _github(b"", private=True))
    with pytest.raises(G.GitHubImportError, match="Private"):
        G.fetch_repository(G.parse_github_url("acme/app"))


def test_rate_limit_message(monkeypatch):
    _mock(monkeypatch, _github(b"", status=403))
    with pytest.raises(G.GitHubImportError, match="rate limit"):
        G.fetch_repository(G.parse_github_url("acme/app"))


@pytest.mark.parametrize("target", ["https://169.254.169.254/latest/meta-data", "http://codeload.github.com/x",
                                    "https://127.0.0.1/a.zip", "https://evil.example/a.zip"])
def test_archive_redirect_to_disallowed_host_blocked(monkeypatch, target):
    _mock(monkeypatch, _github(b"", archive_redirect=target))
    with pytest.raises(G.GitHubImportError, match="blocked"):
        G.fetch_repository(G.parse_github_url("acme/app"))


def test_oversized_archive_rejected(monkeypatch):
    from sentinel.config import Limits
    monkeypatch.setattr(G, "LIMITS", Limits(max_upload_bytes=1000))
    _mock(monkeypatch, _github(b"PK" + b"0" * 5000))
    with pytest.raises(G.GitHubImportError, match="exceeds"):
        G.fetch_repository(G.parse_github_url("acme/app"))


def test_hostile_archive_contents_rejected(monkeypatch):
    zipped = make_zip({"app/../../escape.txt": "x", "app/package.json": {"dependencies": {}}})
    _mock(monkeypatch, _github(zipped))
    src, _ = G.fetch_repository(G.parse_github_url("acme/app"))
    assert "escape.txt" not in " ".join(src.list_files())
    assert src.report.rejected


def test_api_endpoint_validation(monkeypatch):
    from fastapi.testclient import TestClient
    from sentinel import db
    from sentinel.app import app
    with TestClient(app) as c:
        h = {"X-Sentinel-Client": "test"}
        c.put("/api/settings", json={"offline_mode": False}, headers=h)
        assert c.post("/api/scans/github", json={"url": "https://gitlab.com/o/r"}, headers=h).status_code == 400
        assert c.post("/api/scans/github", json={"url": "https://github.com/o/r", "ref": "../x"}, headers=h).status_code == 400
        assert c.post("/api/scans/github", json={"url": "https://github.com/o/r", "offline": True}, headers=h).status_code == 409
        assert c.post("/api/scans/github", json={"url": "https://github.com/o/r"}).status_code == 403   # CSRF header
        zipped = make_zip({"app-main/requirements.txt": "six==1.16.0\n"})
        _mock(monkeypatch, _github(zipped))
        r = c.post("/api/scans/github", json={"url": "https://github.com/acme/app"}, headers=h)
        assert r.status_code == 200
        import time
        for _ in range(200):
            st = c.get(f"/api/scans/{r.json()['scan_id']}").json()
            if st["status"] not in ("queued", "running"):
                break
            time.sleep(0.1)
        assert st["status"] == "completed", st
        res = c.get(f"/api/scans/{r.json()['scan_id']}/result").json()
        assert res["scan"]["source"]["commit"] == SHA
        c.put("/api/settings", json={"offline_mode": True}, headers=h)
        db.log_event("test", "done")
