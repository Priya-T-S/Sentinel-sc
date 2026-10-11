"""Deterministic vulnerability matching from OSV data.

For each package with an exact version:
1. OSV reports matching advisory IDs (version-specific query).
2. Advisory records are fetched; withdrawn advisories are dropped.
3. The affected range is re-evaluated locally with ecosystem-aware version comparison
   as an independent cross-check ("applies to installed version").
4. Advisories that alias each other (e.g. GHSA + CVE + duplicate GHSA) are merged into ONE
   finding so a single flaw never counts twice.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from .. import cvss, versions
from ..models import Package
from ..parsers.base import norm_pypi

SEV_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _iso(ts: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def _same_pkg(eco: str, a: str, b: str) -> bool:
    if eco == "PyPI":
        return norm_pypi(a) == norm_pypi(b)
    if eco == "NuGet":
        return a.lower() == b.lower()
    return a == b


def _affected_entries(adv: dict, pkg: Package) -> list[dict]:
    out = []
    for aff in adv.get("affected") or []:
        p = (aff or {}).get("package") or {}
        if p.get("ecosystem", "").split(":")[0] == pkg.ecosystem and _same_pkg(pkg.ecosystem, p.get("name", ""), pkg.name):
            out.append(aff)
    return out


def _severity(adv: dict) -> dict:
    vec3 = vec4 = None
    for s in adv.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            vec3 = s.get("score")
        elif s.get("type") == "CVSS_V4":
            vec4 = s.get("score")
    score = cvss.base_score_v3(vec3) if vec3 else None
    label_src = (adv.get("database_specific") or {}).get("severity")
    label = SEV_LABELS.get(str(label_src).upper()) if label_src else None
    if score is not None:
        sev, basis = cvss.severity_from_score(score), f"CVSS {vec3.split('/')[0].split(':')[1]} base score {score} computed from vector"
    elif label:
        sev, basis = label, f"Qualitative severity '{label_src}' from advisory database (no CVSS v3 vector)"
    else:
        sev, basis = "unknown", "Advisory provides no CVSS vector or severity rating"
    return {"cvss_vector": vec3 or vec4, "cvss_version": "3" if vec3 else ("4" if vec4 else None),
            "cvss_score": score, "severity": sev, "severity_basis": basis,
            "network": cvss.network_exploitable(vec3 or vec4)}


def _symbols(affected: list[dict]) -> list[str]:
    syms = []
    for aff in affected:
        es = aff.get("ecosystem_specific") or {}
        for imp in es.get("imports") or []:
            for s in imp.get("symbols") or []:
                if isinstance(s, str) and s not in syms:
                    syms.append(s)
        for s in es.get("affected_functions") or []:
            if isinstance(s, str) and s not in syms:
                syms.append(s.rsplit(".", 1)[-1])
    return syms[:50]


def match_package(pkg: Package, ids: list[str], details: dict[str, dict], query_origin: str, query_ts: Optional[float]) -> list[dict]:
    advisories = []
    for vid in ids:
        rec = details.get(vid) or {}
        adv = rec.get("data")
        if not adv:
            advisories.append({"id": vid, "missing": True, "origin": rec.get("origin", "unavailable")})
            continue
        if adv.get("withdrawn"):
            continue
        advisories.append({"id": vid, "adv": adv, "origin": rec.get("origin"), "fetched_at": rec.get("fetched_at")})

    # ---- merge alias groups (union-find over id + aliases)
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra
    for a in advisories:
        find(a["id"])
        for al in (a.get("adv") or {}).get("aliases") or []:
            union(a["id"], al)
    groups: dict[str, list[dict]] = {}
    for a in advisories:
        groups.setdefault(find(a["id"]), []).append(a)

    findings = []
    for members in groups.values():
        findings.append(_build_finding(pkg, members, query_origin, query_ts))
    return findings


def _primary(members: list[dict]) -> dict:
    def rank(m):
        adv = m.get("adv") or {}
        has_sev = bool(adv.get("severity")) or bool((adv.get("database_specific") or {}).get("severity"))
        reviewed = bool((adv.get("database_specific") or {}).get("github_reviewed"))
        return (0 if m.get("adv") else 1, 0 if has_sev else 1, 0 if reviewed else 1, m["id"])
    return sorted(members, key=rank)[0]


def _build_finding(pkg: Package, members: list[dict], query_origin: str, query_ts: Optional[float]) -> dict:
    prim = _primary(members)
    adv = prim.get("adv") or {}
    ids = sorted({m["id"] for m in members})
    aliases = sorted({al for m in members for al in ((m.get("adv") or {}).get("aliases") or [])} | set(ids))
    cves = [a for a in aliases if a.startswith("CVE-")]
    affected = _affected_entries(adv, pkg) if adv else []
    applies = None
    ranges: list[str] = []
    fixed: list[str] = []
    member_min_fixed: list[str] = []
    for m in members:
        mfixed: list[str] = []
        for aff in _affected_entries(m.get("adv") or {}, pkg):
            mfixed.extend(versions.osv_fixed_versions(pkg.ecosystem, pkg.version, aff))
            r = versions.osv_affected(pkg.ecosystem, pkg.version, aff)
            if r is True:
                applies = True
            elif r is False and applies is None:
                applies = False
            ranges.extend(x for x in versions.describe_osv_ranges(aff) if x not in ranges)
        fixed.extend(mfixed)
        if mfixed:
            member_min_fixed.append(versions.sort_versions(pkg.ecosystem, mfixed)[0])
    fixed = versions.sort_versions(pkg.ecosystem, list(dict.fromkeys(fixed)))
    # Aliased records can publish different fixed versions (e.g. an incomplete earlier fix):
    # the group is only fixed once EVERY member's first fixed version is reached.
    fixed_all = versions.sort_versions(pkg.ecosystem, member_min_fixed)[-1] if member_min_fixed else None
    sev = _severity(adv) if adv else {"severity": "unknown", "severity_basis": "Advisory details unavailable",
                                      "cvss_score": None, "cvss_vector": None, "cvss_version": None, "network": None}
    if sev["severity"] == "unknown":
        for m in members:  # fall back to any alias that has a rating (no inflation: max of one flaw)
            if m.get("adv"):
                s2 = _severity(m["adv"])
                if s2["severity"] != "unknown":
                    sev = s2
                    break
    cwes = sorted({c for m in members for c in (((m.get("adv") or {}).get("database_specific") or {}).get("cwe_ids") or [])})
    refs = []
    seen_urls = set()
    for m in members:
        for r in (m.get("adv") or {}).get("references") or []:
            u = r.get("url") if isinstance(r, dict) else None
            if isinstance(u, str) and u.startswith(("https://", "http://")) and u not in seen_urls:
                seen_urls.add(u)
                refs.append({"type": r.get("type", "WEB"), "url": u[:500]})
    exploit_refs = [r for r in refs if r["type"] in ("EVIDENCE",) or re.search(r"exploit-db|/exploits?/|packetstorm", r["url"], re.I)]
    origins = sorted({m.get("origin") or "unavailable" for m in members})
    fetched = [m.get("fetched_at") for m in members if m.get("fetched_at")]

    evidence = [
        {"observation": f"OSV reports {', '.join(ids)} for {pkg.name}@{pkg.version} ({pkg.ecosystem})",
         "source": "OSV.dev /v1/querybatch", "url": f"https://osv.dev/vulnerability/{prim['id']}",
         "retrieved_at": _iso(query_ts), "origin": query_origin},
    ]
    if applies is True:
        evidence.append({"observation": f"Installed version {pkg.version} falls inside affected range(s): {'; '.join(ranges[:4])}",
                         "source": "Local range evaluation (SENTINEL-SC version comparator)", "origin": "computed"})
    elif applies is False:
        evidence.append({"observation": f"Local evaluation of the published ranges ({'; '.join(ranges[:4])}) did NOT place "
                                        f"{pkg.version} inside them; OSV's match is kept but flagged for review.",
                         "source": "Local range evaluation", "origin": "computed"})
    else:
        evidence.append({"observation": "Affected ranges could not be evaluated locally (e.g. GIT-only ranges or unparsable "
                                        "versions); relying on OSV's match.", "source": "Local range evaluation", "origin": "computed"})
    if pkg.version_exact:
        evidence.append({"observation": f"Version {pkg.version} taken from {pkg.source_file}", "source": "Lockfile/manifest parser",
                         "origin": "computed"})
    for m in members:
        if m.get("missing"):
            evidence.append({"observation": f"Advisory {m['id']} details could not be retrieved", "source": "OSV.dev", "origin": "unavailable"})

    if applies is False:
        confidence = "medium"
    elif pkg.version_exact and adv:
        confidence = "high"
    elif adv:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "kind": "vulnerability",
        "category": "Known vulnerability",
        "package_id": pkg.id,
        "title": (adv.get("summary") or f"Vulnerability {prim['id']} in {pkg.name}")[:300],
        "severity": sev["severity"],
        "confidence": confidence,
        "verified": bool(adv) and applies is not False,
        "advisory": {
            "id": prim["id"],
            "ids": ids,
            "aliases": aliases,
            "cves": cves,
            "summary": (adv.get("summary") or "")[:500],
            "details": (adv.get("details") or "")[:4000],
            "published": adv.get("published"),
            "modified": adv.get("modified"),
            "cwes": cwes,
            "references": refs[:30],
            "exploit_references": exploit_refs[:10],
            "affected_ranges": ranges[:10],
            "fixed_versions": fixed,
            "first_fixed": fixed_all,
            "applies_to_installed": applies,
            "symbols": _symbols(affected),
            "source_url": f"https://osv.dev/vulnerability/{prim['id']}",
            "database_source": ((affected[0].get("database_specific") or {}).get("source") if affected else None),
            "retrieved_at": _iso(max(fetched)) if fetched else None,
            "origin": origins,
            **sev,
        },
        "evidence": evidence,
    }
