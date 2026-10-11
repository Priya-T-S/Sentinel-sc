"""Registry metadata (npm, PyPI), OpenSSF Scorecard, CISA KEV and FIRST EPSS providers.

Raw registry documents can be very large (full npm packuments), so only the fields used by
heuristics and remediation are extracted and cached.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, urlparse

from . import IntelContext
from .http import request_json

NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"
SCORECARD = "https://api.securityscorecards.dev/projects"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"


def _iso(ts: Optional[str]) -> Optional[str]:
    return ts if isinstance(ts, str) and len(ts) < 40 else None


def _repo_url(raw) -> Optional[str]:
    if isinstance(raw, dict):
        raw = raw.get("url")
    if not isinstance(raw, str):
        return None
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[#/].*)?$", raw)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}"
    return raw[:200] if raw.startswith("https://") else None


def _npm_extract(doc: dict) -> dict:
    times = doc.get("time") or {}
    vers = doc.get("versions") or {}
    out_versions = {}
    for v, meta in list(vers.items())[-3000:]:
        if not isinstance(meta, dict):
            continue
        scripts = meta.get("scripts") or {}
        dist = meta.get("dist") or {}
        out_versions[v] = {
            "published": _iso(times.get(v)),
            "install_scripts": {k: str(scripts[k])[:300] for k in ("preinstall", "install", "postinstall", "prepare")
                                if isinstance(scripts, dict) and k in scripts},
            "deprecated": str(meta["deprecated"])[:300] if meta.get("deprecated") else None,
            "has_provenance": bool((dist.get("attestations") or {}).get("provenance")),
            "has_signatures": bool(dist.get("signatures")),
            "integrity": dist.get("integrity"),
            "dependencies": {k: str(s)[:100] for k, s in list((meta.get("dependencies") or {}).items())[:300]},
            "publisher": ((meta.get("_npmUser") or {}).get("name") if isinstance(meta.get("_npmUser"), dict) else None),
            "license": meta.get("license") if isinstance(meta.get("license"), str) else None,
        }
    return {
        "name": doc.get("name"),
        "created": _iso(times.get("created")),
        "modified": _iso(times.get("modified")),
        "dist_tags": {k: v for k, v in (doc.get("dist-tags") or {}).items() if isinstance(v, str)},
        "maintainers": [m.get("name") for m in (doc.get("maintainers") or []) if isinstance(m, dict)][:50],
        "repository": _repo_url(doc.get("repository")),
        "license": doc.get("license") if isinstance(doc.get("license"), str) else None,
        "versions": out_versions,
        "description": str(doc.get("description") or "")[:300],
    }


def npm_metadata(ictx: IntelContext, name: str) -> tuple[Optional[dict], str, Optional[float]]:
    path = quote(name, safe="@") if name.startswith("@") else quote(name, safe="")
    if name.startswith("@"):
        path = "@" + quote(name[1:], safe="")
    return ictx.lookup("npm", f"npm:pkg:{name}",
                       lambda: _npm_extract(request_json("GET", f"{NPM}/{path}", max_bytes=40 * 1024 * 1024) or {}))


def _pypi_extract(doc: dict) -> dict:
    info = doc.get("info") or {}
    releases = doc.get("releases") or {}
    vers = {}
    for v, files in list(releases.items())[-2000:]:
        times = [f.get("upload_time_iso_8601") for f in (files or []) if isinstance(f, dict) and f.get("upload_time_iso_8601")]
        yanked = any(f.get("yanked") for f in (files or []) if isinstance(f, dict))
        vers[v] = {"published": min(times) if times else None, "yanked": yanked,
                   "has_provenance": None}
    created = min((x["published"] for x in vers.values() if x["published"]), default=None)
    urls = info.get("project_urls") or {}
    repo = None
    for k, u in (urls.items() if isinstance(urls, dict) else []):
        r = _repo_url(u)
        if r and "github.com" in r:
            repo = r
            break
    return {
        "name": info.get("name"),
        "created": created,
        "latest": info.get("version"),
        "license": (info.get("license") or "")[:100] or None,
        "repository": repo or _repo_url(info.get("home_page")),
        "maintainers": [x for x in [info.get("maintainer"), info.get("author")] if x][:5],
        "versions": vers,
        "description": str(info.get("summary") or "")[:300],
    }


def pypi_metadata(ictx: IntelContext, name: str) -> tuple[Optional[dict], str, Optional[float]]:
    return ictx.lookup("pypi", f"pypi:pkg:{name}",
                       lambda: _pypi_extract(request_json("GET", f"{PYPI}/{quote(name, safe='')}/json", max_bytes=30 * 1024 * 1024) or {}))


def scorecard(ictx: IntelContext, repo_url: str) -> tuple[Optional[dict], str, Optional[float]]:
    m = re.match(r"^https://github\.com/([\w.-]+)/([\w.-]+)$", repo_url or "")
    if not m:
        return None, "unavailable", None

    def fetch():
        d = request_json("GET", f"{SCORECARD}/github.com/{m.group(1)}/{m.group(2)}") or {}
        return {"score": d.get("score"), "date": d.get("date"),
                "checks": [{"name": c.get("name"), "score": c.get("score"), "reason": str(c.get("reason") or "")[:200]}
                           for c in (d.get("checks") or []) if isinstance(c, dict)][:25]} if d else {}
    return ictx.lookup("scorecard", f"scorecard:{m.group(1)}/{m.group(2)}".lower(), fetch)


def kev_catalog(ictx: IntelContext) -> tuple[Optional[dict], str, Optional[float]]:
    def fetch():
        d = request_json("GET", KEV_URL, max_bytes=20 * 1024 * 1024) or {}
        return {"catalogVersion": d.get("catalogVersion"), "dateReleased": d.get("dateReleased"),
                "cves": {v["cveID"]: {"dateAdded": v.get("dateAdded"), "name": str(v.get("vulnerabilityName", ""))[:200],
                                      "ransomware": v.get("knownRansomwareCampaignUse")}
                         for v in d.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("cveID")}}
    return ictx.lookup("kev", "kev:catalog", fetch)


def epss_scores(ictx: IntelContext, cves: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    cves = sorted({c for c in cves if re.match(r"^CVE-\d{4}-\d{4,7}$", c)})
    for i in range(0, len(cves), 50):
        chunk = cves[i:i + 50]
        key = "epss:" + ",".join(chunk)

        def fetch(chunk=chunk):
            d = request_json("GET", f"{EPSS}?cve={','.join(chunk)}") or {}
            return {r["cve"]: {"epss": float(r["epss"]), "percentile": float(r["percentile"]), "date": r.get("date")}
                    for r in d.get("data") or [] if isinstance(r, dict) and r.get("cve")}
        val, origin, ts = ictx.lookup("epss", key, fetch)
        for c, v in (val or {}).items():
            out[c] = {**v, "origin": origin}
    return out


def days_since(iso: Optional[str], now: Optional[datetime] = None) -> Optional[float]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = now or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).total_seconds() / 86400


def host_of(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except ValueError:
        return None
