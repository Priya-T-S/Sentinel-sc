"""FastAPI application: REST API + static frontend.

Security controls (see docs/THREAT_MODEL.md):
  * Binds to 127.0.0.1 by default; Host-header allow-list blocks DNS-rebinding attacks.
  * State-changing requests require the custom header `X-Sentinel-Client` (cross-site forms/fetches
    cannot add it without a CORS preflight, which this API never approves) -> CSRF protection.
  * No CORS is enabled. Strict CSP and security headers on every response.
  * Upload size/type limits; archives are read in memory with traversal/symlink/bomb protection.
  * Per-client rate limits; bounded concurrent/queued scans; duplicate scans are de-duplicated.
  * Generic error bodies (no stack traces, internal paths or secrets).
"""
from __future__ import annotations

import io
import json
import logging
import os
import re
import threading
import time
import uuid
import zipfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import __version__, db, engine, policy, report, sbom, scoring
from .config import DEMO_APP_DIR, FIXTURE_DIR, FRONTEND_DIST, LIMITS
from .intel import load_fixture
from .jobs import JobManager, QueueFull
from .models import SEVERITY_ORDER
from .parsers import COVERAGE, is_cyclonedx_name
from .reposource import DirSource, SingleFileSource, UnsafeInputError, ZipSource

log = logging.getLogger("sentinel.api")

ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get("SENTINEL_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(",")}
MANIFEST_NAMES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
                  "Pipfile.lock", "pyproject.toml", "go.mod", "Cargo.lock", "Cargo.toml", "pom.xml", "gradle.lockfile",
                  "packages.lock.json", "build.gradle", "build.gradle.kts"}
SCAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")

jobs = JobManager()


@asynccontextmanager
async def lifespan(_app):
    db.init()
    db.mark_interrupted()
    snap = FIXTURE_DIR / "intel-snapshot.json"
    if snap.exists():
        try:
            load_fixture(snap)
        except (OSError, ValueError, KeyError):
            log.warning("could not load intelligence fixture")
    yield


app = FastAPI(title="SENTINEL-SC", version=__version__, docs_url="/api/docs", redoc_url=None,
              openapi_url="/api/openapi.json", lifespan=lifespan)


# --------------------------------------------------------------------------- middleware

class RateLimiter:
    def __init__(self):
        self.hits: dict[tuple, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: tuple, limit: int, window: float) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


limiter = RateLimiter()
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    host = (request.headers.get("host") or "").lower()
    hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
    if hostname not in ALLOWED_HOSTS:
        db.log_event("host_rejected", "request with non-allow-listed Host header")
        return JSONResponse({"error": "Host not allowed"}, status_code=421)
    path = request.url.path
    client = request.client.host if request.client else "unknown"
    if path.startswith("/api/"):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get("x-sentinel-client") not in ("web", "cli", "test"):
                db.log_event("csrf_rejected", f"{request.method} {path[:80]}")
                return JSONResponse({"error": "Missing X-Sentinel-Client header (CSRF protection)."}, status_code=403)
        if not limiter.allow((client, "api"), 600, 60):
            return JSONResponse({"error": "Rate limit exceeded."}, status_code=429, headers={"Retry-After": "30"})
        if request.method == "POST" and ("/scans" in path or "/whatif" in path or path.endswith("/demo/scan")):
            if not limiter.allow((client, "scan"), 20, 60):
                db.log_event("rate_limited", f"scan creation from {client}")
                return JSONResponse({"error": "Too many scan requests. Wait a minute."}, status_code=429, headers={"Retry-After": "60"})
    try:
        response = await call_next(request)
    except Exception:  # pragma: no cover - last-resort guard
        ref = uuid.uuid4().hex[:8]
        log.exception("unhandled error ref=%s", ref)
        response = JSONResponse({"error": f"Internal error (ref {ref})."}, status_code=500)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail if isinstance(exc.detail, str) else "Request error."}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    ref = uuid.uuid4().hex[:8]
    log.exception("unhandled error ref=%s", ref)
    return JSONResponse({"error": f"Internal error (ref {ref})."}, status_code=500)


# --------------------------------------------------------------------------- helpers

def _scan_id(scan_id: str) -> str:
    if not SCAN_ID_RE.match(scan_id or ""):
        raise HTTPException(404, "Scan not found.")
    return scan_id


def _result(scan_id: str) -> dict:
    res = jobs.result(_scan_id(scan_id))
    if res is None:
        row = db.scan_get(scan_id)
        if not row:
            raise HTTPException(404, "Scan not found.")
        raise HTTPException(409, f"Scan is {row['status']}; no result available.")
    return res


def _row(r: dict) -> dict:
    return {"id": r["id"], "created_at": r["created_at"], "finished_at": r["finished_at"], "status": r["status"],
            "source_name": r["source_name"], "source_kind": r["source_kind"], "is_demo": bool(r["is_demo"]),
            "summary": json.loads(r["summary_json"]) if r.get("summary_json") else None, "error": r.get("error")}


# --------------------------------------------------------------------------- meta

@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "active_scans": jobs.active_count()}


@app.get("/api/meta")
def meta():
    return {"version": __version__, "coverage": COVERAGE, "stages": [{"key": k, "label": l} for k, l, _ in engine.STAGES],
            "limits": {k: getattr(LIMITS, k) for k in LIMITS.__dataclass_fields__},
            "scoring": {"doc": scoring.__doc__, "reachability_weights": scoring.REACH_W, "scope_weights": scoring.SCOPE_W,
                        "severity_bands": scoring.SEV_BAND, "heuristic_bands": scoring.HEUR_BAND},
            "upload": {"accepted": [".zip", "CycloneDX .json", *sorted(MANIFEST_NAMES), "requirements*.txt"],
                       "max_bytes": LIMITS.max_upload_bytes},
            "demo_available": DEMO_APP_DIR.is_dir()}


# --------------------------------------------------------------------------- scans

async def _read_upload(file: UploadFile) -> bytes:
    buf = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > LIMITS.max_upload_bytes:
            db.log_event("upload_rejected", "upload exceeded size limit")
            raise HTTPException(413, "Upload exceeds the maximum size.")
    return bytes(buf)


@app.post("/api/scans")
async def create_scan(file: UploadFile = File(...), offline: bool = Form(False)):
    name = os.path.basename((file.filename or "upload").replace("\\", "/"))[:200]
    data = await _read_upload(file)
    if not data:
        raise HTTPException(400, "Empty upload.")
    low = name.lower()
    if low.endswith(".zip"):
        if not data.startswith(b"PK"):
            raise HTTPException(400, "File is not a ZIP archive.")
        try:
            ZipSource(data, name)  # validate synchronously so the user gets an immediate error
        except UnsafeInputError as exc:
            db.log_event("upload_rejected", str(exc)[:120])
            raise HTTPException(400, str(exc))
        make = lambda: ZipSource(data, name)
        kind = "archive"
    elif name in MANIFEST_NAMES or is_cyclonedx_name(name) or re.match(r"^(requirements|constraints).*\.txt$", low) \
            or low.endswith(".csproj"):
        try:
            SingleFileSource(name, data)
        except UnsafeInputError as exc:
            raise HTTPException(400, str(exc))
        make = lambda: SingleFileSource(name, data)
        kind = "sbom" if is_cyclonedx_name(name) else "manifest"
    elif low.endswith(".json"):
        # any JSON: accept only if it is CycloneDX
        try:
            doc = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            raise HTTPException(400, "Unsupported file: JSON is not valid.")
        if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
            raise HTTPException(400, "Unsupported JSON file. Upload a CycloneDX SBOM, a lockfile, or a .zip of the repository.")
        make = lambda: SingleFileSource("sbom.cdx.json", data)
        kind = "sbom"
    else:
        raise HTTPException(400, "Unsupported file type. Upload a .zip of the repository, a supported lockfile/manifest, or a CycloneDX JSON SBOM.")
    try:
        scan_id, dedup = jobs.submit(make, source_name=name, source_kind=kind, content_key=data, offline=offline)
    except QueueFull as exc:
        raise HTTPException(429, str(exc))
    return {"scan_id": scan_id, "deduplicated": dedup}


@app.post("/api/demo/scan")
def demo_scan(offline: bool = Query(False)):
    if not DEMO_APP_DIR.is_dir():
        raise HTTPException(404, "Demo project not found.")
    key = b"demo:" + str(sorted((p.name, p.stat().st_mtime) for p in DEMO_APP_DIR.rglob("*") if p.is_file())).encode()
    try:
        scan_id, dedup = jobs.submit(lambda: DirSource(str(DEMO_APP_DIR)), source_name="demo/acme-orders-api",
                                     source_kind="demo", content_key=key, offline=offline, is_demo=True)
    except QueueFull as exc:
        raise HTTPException(429, str(exc))
    return {"scan_id": scan_id, "deduplicated": dedup}


@app.post("/api/demo/reset")
def demo_reset():
    removed = db.scan_purge(demo_only=True)
    snap = FIXTURE_DIR / "intel-snapshot.json"
    loaded = load_fixture(snap) if snap.exists() else None
    return {"removed_demo_scans": removed, "fixture": loaded}


@app.get("/api/scans")
def list_scans(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return {"items": [_row(r) for r in db.scan_list(limit, offset)]}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    row = db.scan_get(_scan_id(scan_id))
    if not row:
        raise HTTPException(404, "Scan not found.")
    out = _row(row)
    live = jobs.status(scan_id)
    out["progress"] = live["progress"] if live else None
    if live and row["status"] in ("queued", "running"):
        out["status"] = live["status"]
    return out


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    if not jobs.cancel(_scan_id(scan_id)):
        raise HTTPException(409, "Scan is not running.")
    return {"cancelled": True}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    jobs.cancel(_scan_id(scan_id))
    jobs.forget(scan_id)
    if not db.scan_delete(scan_id):
        raise HTTPException(404, "Scan not found.")
    return {"deleted": True}


@app.delete("/api/scans")
def purge_scans():
    for r in db.scan_list(500):
        jobs.forget(r["id"])
    return {"deleted": db.scan_purge()}


@app.get("/api/scans/{scan_id}/result")
def scan_result(scan_id: str):
    res = _result(scan_id)
    # graph and findings have dedicated (paginated) endpoints
    roots = [{"id": n["id"], "name": n["name"], "ecosystem": n["ecosystem"], "manifest": n.get("manifest"),
              "lockfile": n.get("lockfile")} for n in res["graph"]["nodes"] if n["type"] == "root"]
    return {k: v for k, v in res.items() if k not in ("graph", "findings", "packages")} | {
        "package_count": len(res["packages"]), "roots": roots}


@app.get("/api/scans/{scan_id}/findings")
def scan_findings(scan_id: str, q: str = Query("", max_length=200), kind: str = Query("", max_length=100),
                  severity: str = Query("", max_length=100), ecosystem: str = Query("", max_length=100),
                  reachability: str = Query("", max_length=200), remediation: str = Query("", max_length=200),
                  direct: Optional[bool] = None, package_id: str = Query("", max_length=400),
                  sort: str = Query("priority", pattern="^(priority|severity|package|confidence|kind)$"),
                  order: str = Query("desc", pattern="^(asc|desc)$"),
                  page: int = Query(1, ge=1, le=10000), page_size: int = Query(50, ge=1, le=200)):
    res = _result(scan_id)
    pk = res["packages"]
    items = res["findings"]

    def split(s):
        return {x.strip() for x in s.split(",") if x.strip()}
    ks, sv, ec, rc, rm = split(kind), split(severity), split(ecosystem), split(reachability), split(remediation)
    ql = q.lower().strip()
    out = []
    for f in items:
        p = pk.get(f.get("package_id") or "", {})
        if ks and f["kind"] not in ks:
            continue
        if sv and f["severity"] not in sv:
            continue
        if ec and p.get("ecosystem") not in ec:
            continue
        if rc and (f.get("reachability") or {}).get("level") not in rc:
            continue
        if rm and (f.get("remediation") or {}).get("state") not in rm:
            continue
        if direct is not None and (not p or p.get("direct") != direct):
            continue
        if package_id and f.get("package_id") != package_id:
            continue
        if ql:
            hay = " ".join([f["title"], f.get("observation", ""), p.get("name", ""), str(p.get("version", "")),
                            f.get("file") or "", " ".join((f.get("advisory") or {}).get("aliases", [])),
                            (f.get("advisory") or {}).get("id", ""), f.get("signal", "")]).lower()
            if ql not in hay:
                continue
        out.append(f)
    rev = order == "desc"
    keyf = {
        "priority": lambda f: f["scores"]["priority"] if f["scores"]["priority"] is not None else -1,
        "severity": lambda f: SEVERITY_ORDER.get(f["severity"], -1),
        "package": lambda f: (pk.get(f.get("package_id") or "", {}).get("name") or f.get("file") or ""),
        "confidence": lambda f: f["scores"]["confidence"],
        "kind": lambda f: f["kind"],
    }[sort]
    out.sort(key=keyf, reverse=rev)
    total = len(out)
    start = (page - 1) * page_size
    return {"total": total, "page": page, "page_size": page_size, "items": out[start:start + page_size]}


@app.get("/api/scans/{scan_id}/findings/{finding_id}")
def scan_finding(scan_id: str, finding_id: str):
    res = _result(scan_id)
    f = next((x for x in res["findings"] if x["id"] == finding_id), None)
    if not f:
        raise HTTPException(404, "Finding not found.")
    plan = next((p for p in res["remediation"]["plans"] if p["package_id"] == f.get("package_id")), None)
    return {"finding": f, "package": res["packages"].get(f.get("package_id") or ""), "plan": plan}


@app.get("/api/scans/{scan_id}/graph")
def scan_graph(scan_id: str, mode: str = Query("risky", pattern="^(risky|full)$")):
    res = _result(scan_id)
    pk = res["packages"]
    nodes, edges = res["graph"]["nodes"], res["graph"]["edges"]
    if mode == "risky" or len(nodes) > 1500:
        keep = set()
        for f in res["findings"]:
            # risk view follows vulnerabilities and supply-chain/integrity signals, not low-value maintenance notes
            if f["kind"] not in ("vulnerability", "suspicious", "integrity") or f["severity"] == "info":
                continue
            for path in (f.get("paths") or [])[:10]:
                keep.update(path)
        keep |= {n["id"] for n in nodes if n["type"] == "root"}
        keep |= {pid for pid, p in pk.items() if p.get("direct")}
        nodes = [n for n in nodes if n["id"] in keep][:1500]
        ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["from"] in ids and e["to"] in ids]
    out_nodes = []
    for n in nodes:
        if n["type"] == "root":
            out_nodes.append({"id": n["id"], "type": "root", "name": n["name"], "ecosystem": n["ecosystem"], "depth": 0,
                              "manifest": n.get("manifest")})
            continue
        p = pk.get(n["id"], {})
        out_nodes.append({"id": n["id"], "type": "package", "name": p.get("name"), "version": p.get("version"),
                          "ecosystem": p.get("ecosystem"), "direct": p.get("direct"), "scope": p.get("scope"),
                          "depth": p.get("depth"), "max_severity": p.get("max_severity"),
                          "vulnerability_count": p.get("vulnerability_count", 0), "signal_count": p.get("signal_count", 0),
                          "priority": (p.get("risk") or {}).get("priority"), "vuln_status": p.get("vuln_status"),
                          "dependents": p.get("dependents")})
    return {"mode": mode, "total_nodes": len(res["graph"]["nodes"]), "nodes": out_nodes, "edges": edges}


@app.get("/api/scans/{scan_id}/packages")
def scan_packages(scan_id: str, q: str = Query("", max_length=200), page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=500),
                  only_risky: bool = False):
    res = _result(scan_id)
    items = list(res["packages"].values())
    if q:
        items = [p for p in items if q.lower() in p["name"].lower()]
    if only_risky:
        items = [p for p in items if p["finding_ids"]]
    items.sort(key=lambda p: (-(p["risk"]["priority"] or -1), p["name"]))
    slim = [{k: p[k] for k in ("id", "name", "version", "ecosystem", "direct", "scope", "depth", "vuln_status", "vulnerability_count",
                               "signal_count", "max_severity", "risk", "dependents", "source_type")} for p in items]
    start = (page - 1) * page_size
    return {"total": len(slim), "items": slim[start:start + page_size]}


@app.get("/api/scans/{scan_id}/package")
def scan_package(scan_id: str, id: str = Query(..., max_length=400)):
    res = _result(scan_id)
    p = res["packages"].get(id)
    if not p:
        raise HTTPException(404, "Package not found.")
    fs = [f for f in res["findings"] if f.get("package_id") == id]
    plan = next((pl for pl in res["remediation"]["plans"] if pl["package_id"] == id), None)
    paths = next((f["paths"] for f in fs if f.get("paths")), None)
    if paths is None:
        # compute from stored graph edges
        paths = _paths_from_graph(res, id)
    deps = [e["to"] for e in res["graph"]["edges"] if e["from"] == id]
    parents = [e["from"] for e in res["graph"]["edges"] if e["to"] == id]
    return {"package": p, "findings": fs, "plan": plan, "paths": paths[:25],
            "dependencies": [{"id": d, "name": res["packages"].get(d, {}).get("name"), "version": res["packages"].get(d, {}).get("version")} for d in deps],
            "dependents": [{"id": d, "name": res["packages"].get(d, {}).get("name", d), "version": res["packages"].get(d, {}).get("version")} for d in parents]}


def _paths_from_graph(res: dict, target: str, limit: int = 25) -> list:
    from .models import DependencyGraph, Root
    g = DependencyGraph()
    for n in res["graph"]["nodes"]:
        if n["type"] == "root":
            g.roots[n["id"]] = Root(n["id"], n["name"], n["ecosystem"], n.get("manifest") or "")
    for e in res["graph"]["edges"]:
        g.add_edge(e["from"], e["to"])
    return g.paths_to(target, limit)


class WhatIf(BaseModel):
    changes: Optional[dict[str, str]] = Field(default=None, max_length=500)


@app.post("/api/scans/{scan_id}/whatif")
def scan_whatif(scan_id: str, body: WhatIf):
    res = _result(scan_id)
    if body.changes:
        for k, v in body.changes.items():
            if k not in res["packages"] or not re.match(r"^[0-9A-Za-z.+_~-]{1,64}$", v):
                raise HTTPException(400, "Invalid change: unknown package or malformed version.")
    return engine.whatif(res, body.changes, offline=bool(db.get_settings().get("offline_mode")) or res["scan"]["offline"])


@app.get("/api/scans/{scan_id}/export/{fmt}")
def export(scan_id: str, fmt: str):
    res = _result(scan_id)
    base = f"sentinel-{scan_id}"
    if fmt == "json":
        return Response(json.dumps(res, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{base}.json"'})
    if fmt == "html":
        return HTMLResponse(report.render_html(res), headers={"Content-Disposition": f'attachment; filename="{base}.html"',
                                                              "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    if fmt == "cyclonedx":
        return Response(json.dumps(sbom.export_cyclonedx(res), indent=2), media_type="application/vnd.cyclonedx+json",
                        headers={"Content-Disposition": f'attachment; filename="{base}.cdx.json"'})
    if fmt == "gate":
        return Response(json.dumps(res["policy"], indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{base}-gate.json"'})
    if fmt == "patch":
        cp = (res["remediation"].get("combined_patch") or {}).get("files") or []
        if not cp:
            raise HTTPException(404, "No patch available for this scan.")
        return PlainTextResponse("".join(f["diff"] for f in cp), headers={"Content-Disposition": f'attachment; filename="{base}.diff"'})
    raise HTTPException(404, "Unknown export format.")


@app.get("/api/compare/{base_id}/{head_id}")
def compare(base_id: str, head_id: str):
    a, b = _result(base_id), _result(head_id)

    def index(res):
        return {f["fingerprint"]: f for f in res["findings"]}
    ia, ib = index(a), index(b)

    def brief(f, res):
        p = res["packages"].get(f.get("package_id") or "", {})
        return {"fingerprint": f["fingerprint"], "kind": f["kind"], "title": f["title"], "severity": f["severity"],
                "package": p.get("name") or f.get("file"), "version": p.get("version"),
                "advisory": (f.get("advisory") or {}).get("id"), "priority": f["scores"]["priority"]}
    new = [brief(ib[k], b) for k in ib if k not in ia]
    removed = [brief(ia[k], a) for k in ia if k not in ib]
    changed = []
    for k in ia.keys() & ib.keys():
        fa, fb = brief(ia[k], a), brief(ib[k], b)
        diffs = {f: (fa[f], fb[f]) for f in ("version", "severity", "priority") if fa[f] != fb[f]}
        ea, eb = ia[k].get("evidence", []), ib[k].get("evidence", [])
        if [e.get("observation") for e in ea] != [e.get("observation") for e in eb]:
            diffs["evidence"] = ("changed", "changed")
        if diffs:
            changed.append({**fb, "changes": diffs})
    pa = {(p["ecosystem"], p["name"]): p["version"] for p in a["packages"].values()}
    pb = {(p["ecosystem"], p["name"]): p["version"] for p in b["packages"].values()}
    return {
        "base": {"id": base_id, "finished_at": a["scan"]["finished_at"], "summary": a["summary"]["severity"]},
        "head": {"id": head_id, "finished_at": b["scan"]["finished_at"], "summary": b["summary"]["severity"]},
        "new_findings": new, "removed_findings": removed, "changed_findings": changed,
        "packages_added": [{"ecosystem": k[0], "name": k[1], "version": v} for k, v in pb.items() if k not in pa][:500],
        "packages_removed": [{"ecosystem": k[0], "name": k[1], "version": v} for k, v in pa.items() if k not in pb][:500],
        "packages_changed": [{"ecosystem": k[0], "name": k[1], "from": pa[k], "to": v} for k, v in pb.items() if k in pa and pa[k] != v][:500],
    }


# --------------------------------------------------------------------------- policy & settings

@app.get("/api/policy")
def get_policy():
    return {"policy": policy.current_policy(), "default": policy.DEFAULT_POLICY}


@app.put("/api/policy")
def put_policy(body: dict[str, Any]):
    try:
        pol = policy.validate(body.get("policy", body))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.put_setting("policy", pol)
    return {"policy": pol}


@app.post("/api/scans/{scan_id}/policy")
def evaluate_policy(scan_id: str, body: Optional[dict[str, Any]] = None):
    res = _result(scan_id)
    try:
        pol = policy.validate((body or {}).get("policy")) if body and body.get("policy") else policy.current_policy()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return policy.evaluate(res, pol)


class SettingsBody(BaseModel):
    offline_mode: Optional[bool] = None
    retention_days: Optional[int] = Field(default=None, ge=0, le=3650)
    enable_registry_metadata: Optional[bool] = None
    enable_scorecard: Optional[bool] = None
    enable_epss_kev: Optional[bool] = None


@app.get("/api/settings")
def get_settings():
    s = db.get_settings()
    s.pop("policy", None)
    return s


@app.put("/api/settings")
def put_settings(body: SettingsBody):
    for k, v in body.model_dump(exclude_none=True).items():
        db.put_setting(k, v)
    return get_settings()


@app.get("/api/providers")
def providers():
    latest = next((r for r in db.scan_list(20) if r["status"] == "completed"), None)
    status = None
    if latest:
        res = jobs.result(latest["id"])
        status = {"scan_id": latest["id"], "finished_at": latest["finished_at"], "providers": res["providers"] if res else None}
    snap = FIXTURE_DIR / "intel-snapshot.json"
    fixture = None
    if snap.exists():
        try:
            d = json.loads(snap.read_text(encoding="utf-8"))
            fixture = {"created_at": d.get("created_at"), "entries": len(d.get("entries", {})), "description": d.get("description")}
        except (OSError, ValueError):
            fixture = {"error": "unreadable"}
    return {"cache": db.cache_stats(), "last_scan": status, "fixture": fixture, "settings": get_settings()}


@app.post("/api/providers/check")
def providers_check():
    """Live connectivity probe of each provider (tiny requests, no project data sent)."""
    from .intel.http import ProviderError, RequestBlocked, request_json
    probes = {
        "osv": ("POST", "https://api.osv.dev/v1/query", {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"}),
        "npm": ("GET", "https://registry.npmjs.org/-/ping", None),
        "pypi": ("GET", "https://pypi.org/pypi/pip/json", None),
        "epss": ("GET", "https://api.first.org/data/v1/epss?cve=CVE-2021-44228", None),
    }
    out = {}
    for name, (m, url, body) in probes.items():
        t = time.time()
        try:
            request_json(m, url, body=body, retries=0)
            out[name] = {"ok": True, "ms": round((time.time() - t) * 1000)}
        except (ProviderError, RequestBlocked) as exc:
            out[name] = {"ok": False, "error": str(exc)[:120]}
    return out


@app.delete("/api/cache")
def clear_cache(include_fixture: bool = False):
    db.cache_clear(None if include_fixture else "live")
    return {"cleared": True}


@app.get("/api/security-events")
def security_events():
    return {"items": db.recent_events(100)}


# --------------------------------------------------------------------------- frontend

@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(404, "Not found.")
    dist = FRONTEND_DIST.resolve()
    if not dist.is_dir():
        return HTMLResponse("<h1>SENTINEL-SC API</h1><p>Frontend not built. Run <code>npm run build</code> in /frontend, "
                            "or use the Vite dev server.</p>", status_code=200)
    candidate = (dist / full_path).resolve()
    if full_path and candidate.is_relative_to(dist) and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(dist / "index.html")
