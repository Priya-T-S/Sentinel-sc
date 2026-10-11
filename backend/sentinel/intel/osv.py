"""OSV.dev provider: batched version-specific queries + advisory detail retrieval."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .. import db
from ..models import Package
from . import IntelContext
from .http import ProviderError, RequestBlocked, request_json

OSV_API = "https://api.osv.dev/v1"
SUPPORTED = {"npm", "PyPI", "Go", "crates.io", "Maven", "NuGet"}
BATCH = 500


def osv_name(pkg_ecosystem: str, name: str) -> str:
    return name


def _qkey(eco: str, name: str, version: str) -> str:
    return f"osv:q:{eco}:{name}:{version}"


def query_versions(ictx: IntelContext, items: list[tuple[str, str, str]], progress=None) -> dict[tuple, dict]:
    """items: (ecosystem, name, version). Returns {(eco,name,ver): {"ids": [...], "origin", "fetched_at"}}.

    Packages whose lookup failed get origin "unavailable" and ids None.
    """
    st = ictx.providers["osv"]
    results: dict[tuple, dict] = {}
    todo: list[tuple[str, str, str]] = []
    for it in dict.fromkeys(items):
        hit = db.cache_get(_qkey(*it), None)
        if hit is not None:
            value, ts, origin = hit
            import time as _t
            fresh = (_t.time() - ts) <= 6 * 3600
            if ictx.offline or (fresh and origin != "fixture"):
                with ictx._lock:
                    if origin == "fixture":
                        st.fixture_hits += 1
                    else:
                        st.cache_hits += 1
                    st.note_data(ts)
                results[it] = {"ids": value, "origin": "fixture" if origin == "fixture" else "cache", "fetched_at": ts}
                continue
        todo.append(it)
    if ictx.offline:
        for it in todo:
            results[it] = {"ids": None, "origin": "unavailable", "fetched_at": None}
            st.misses += 1
        return results
    for i in range(0, len(todo), BATCH):
        if ictx.cancelled():
            break
        chunk = todo[i:i + BATCH]
        body = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
        try:
            resp = request_json("POST", f"{OSV_API}/querybatch", body=body, max_bytes=16 * 1024 * 1024)
            rows = (resp or {}).get("results") or []
            if len(rows) != len(chunk):
                raise ProviderError("OSV batch response length mismatch")
            import time as _t
            now = _t.time()
            for it, row in zip(chunk, rows):
                ids = [v["id"] for v in (row or {}).get("vulns") or [] if isinstance(v, dict) and isinstance(v.get("id"), str)]
                if (row or {}).get("next_page_token"):
                    ids = _paginate_single(it, ids)
                db.cache_put(_qkey(*it), "osv", ids, "live", now)
                results[it] = {"ids": ids, "origin": "live", "fetched_at": now}
            with ictx._lock:
                st.live_calls += 1
                st.note_data(now)
        except (ProviderError, RequestBlocked) as exc:
            st.error(f"querybatch: {exc}")
            for it in chunk:
                hit = db.cache_get(_qkey(*it), None)
                if hit is not None:
                    value, ts, origin = hit
                    if origin == "fixture":
                        st.fixture_hits += 1
                    else:
                        st.stale_hits += 1
                    st.note_data(ts)
                    results[it] = {"ids": value, "origin": "fixture" if origin == "fixture" else "stale", "fetched_at": ts}
                else:
                    st.misses += 1
                    results[it] = {"ids": None, "origin": "unavailable", "fetched_at": None}
        if progress:
            progress(min(i + BATCH, len(todo)), len(todo))
    for it in todo:
        results.setdefault(it, {"ids": None, "origin": "unavailable", "fetched_at": None})
    return results


def _paginate_single(it, ids: list[str]) -> list[str]:
    eco, name, version = it
    token = None
    for _ in range(10):
        body = {"package": {"name": name, "ecosystem": eco}, "version": version}
        if token:
            body["page_token"] = token
        resp = request_json("POST", f"{OSV_API}/query", body=body) or {}
        for v in resp.get("vulns") or []:
            if v.get("id") not in ids:
                ids.append(v["id"])
        token = resp.get("next_page_token")
        if not token:
            break
    return ids


def _trim(v: dict) -> dict:
    """Keep the advisory fields we use; cap free-text sizes."""
    keep = {k: v.get(k) for k in ("id", "aliases", "related", "summary", "details", "severity", "affected", "references",
                                  "published", "modified", "withdrawn", "database_specific", "schema_version")}
    if isinstance(keep.get("details"), str) and len(keep["details"]) > 6000:
        keep["details"] = keep["details"][:6000] + "\n[truncated]"
    if isinstance(keep.get("references"), list):
        keep["references"] = keep["references"][:40]
    return keep


def fetch_vulns(ictx: IntelContext, ids: list[str], progress=None) -> dict[str, dict]:
    """Return {id: {"data": advisory|None, "origin", "fetched_at"}}."""
    out: dict[str, dict] = {}
    uniq = [i for i in dict.fromkeys(ids) if isinstance(i, str) and len(i) < 100]

    def one(vid: str):
        if ictx.cancelled():
            return vid, (None, "unavailable", None)
        safe = "".join(ch for ch in vid if ch.isalnum() or ch in "-_:.")
        return vid, ictx.lookup("osv", f"osv:v:{safe}",
                                lambda: _trim(request_json("GET", f"{OSV_API}/vulns/{safe}") or {}), ttl_key="osv_vuln")
    done = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for vid, (data, origin, ts) in pool.map(one, uniq):
            out[vid] = {"data": data if data else None, "origin": origin, "fetched_at": ts}
            done += 1
            if progress and done % 5 == 0:
                progress(done, len(uniq))
    return out


def check_candidate_versions(ictx: IntelContext, eco: str, name: str, versions: list[str]) -> dict[str, Optional[list[str]]]:
    """Used by remediation: which of these versions have known advisories? None = could not verify."""
    res = query_versions(ictx, [(eco, name, v) for v in versions])
    return {v: res[(eco, name, v)]["ids"] for v in versions}


def eligible(pkg: Package) -> bool:
    return pkg.ecosystem in SUPPORTED and bool(pkg.version) and pkg.source_type in ("registry", "unknown")
