"""Agent 2 - Vulnerability Intelligence (deterministic).

Matches every exact package version against OSV, retrieves advisory records, re-checks affected ranges
locally, merges aliases (one flaw = one finding) and attaches CISA KEV / FIRST EPSS exploitation evidence.
"""
from __future__ import annotations

from ..analyzers import vulns
from ..intel import osv as osv_provider
from ..intel import registry as reg
from .base import Board

NAME = "vuln_intel"


def _iso(ts):
    from ..engine import _iso as iso
    return iso(ts)


def run(b: Board) -> dict:
    pr = b.progress
    pr.start("osv")
    eligible = [p for p in b.graph.packages.values() if osv_provider.eligible(p)]
    q = osv_provider.query_versions(b.ictx, [(p.ecosystem, p.name, p.version) for p in eligible],
                                    progress=lambda d, t: pr.sub("osv", d, t, f"{d}/{t} package versions queried"))
    pr.done("osv", f"{len(eligible)} exact version(s) checked")
    all_ids = sorted({i for r in q.values() for i in (r["ids"] or [])})
    pr.start("advisories", f"{len(all_ids)} advisory record(s)")
    details = osv_provider.fetch_vulns(b.ictx, all_ids, progress=lambda d, t: pr.sub("advisories", d, t, f"{d}/{t} advisories retrieved"))

    eligible_ids = {p.id for p in eligible}
    findings: list[dict] = []
    for p in b.graph.packages.values():
        info = {"vuln_status": "not_applicable", "vuln_status_code": None, "vuln_status_reason": "", "osv_origin": None,
                "osv_checked_at": None}
        if p.id in eligible_ids:
            r = q.get((p.ecosystem, p.name, p.version)) or {"ids": None, "origin": "unavailable"}
            info["osv_origin"], info["osv_checked_at"] = r["origin"], _iso(r.get("fetched_at"))
            if r["ids"] is None:
                info["vuln_status"], info["vuln_status_code"] = "unverified", "intel_unavailable"
                info["vuln_status_reason"] = "Vulnerability intelligence unavailable for this package (provider error/offline, no cached data)."
            else:
                info["vuln_status"] = "checked"
                findings.extend(vulns.match_package(p, r["ids"], details, r["origin"], r.get("fetched_at")))
        elif not p.version:
            info["vuln_status"], info["vuln_status_code"] = "unverified", "no_exact_version"
            info["vuln_status_reason"] = "No exact version (range only / no lockfile): cannot be matched to advisories."
        elif p.source_type in ("file", "git", "url", "workspace"):
            info["vuln_status_reason"] = f"Non-registry source ({p.source_type}); advisory databases key on registry releases."
        else:
            info["vuln_status_reason"] = f"Ecosystem '{p.ecosystem}' not covered by the vulnerability provider."
        b.pkg_info[p.id] = info
    pr.done("advisories", f"{len(findings)} finding(s) after alias merge")

    # ---- exploitation evidence
    pr.start("exploit")
    cves = sorted({c for f in findings for c in f["advisory"]["cves"]})
    kev_hits, epss, kev_available, kev_origin = {}, {}, False, None
    if cves and b.ictx.enable_epss_kev and not b.cancel.is_set():
        cat, kev_origin, _ = reg.kev_catalog(b.ictx)
        if cat:
            kev_available = True
            for c in cves:
                if c in cat.get("cves", {}):
                    kev_hits[c] = {"cve": c, **cat["cves"][c], "catalog_version": cat.get("catalogVersion"), "origin": kev_origin}
        epss = reg.epss_scores(b.ictx, cves)
    for f in findings:
        kev = next((kev_hits[c] for c in f["advisory"]["cves"] if c in kev_hits), None)
        ep = max((epss[c] for c in f["advisory"]["cves"] if c in epss), key=lambda x: x["epss"], default=None)
        if kev:
            summary = "Listed in CISA KEV: exploited in the wild"
        elif not f["advisory"]["cves"]:
            summary = "No CVE alias, so CISA KEV cannot be checked"
        elif kev_available:
            summary = f"Not listed in CISA KEV ({kev_origin} catalog); absence is not proof of non-exploitation"
        else:
            summary = "Exploitation status not verified (KEV catalog unavailable)"
        f["exploitation"] = {"kev": kev, "epss": ep, "kev_checked": kev_available,
                             "exploit_references": f["advisory"].get("exploit_references", []), "summary": summary}
    pr.done("exploit", f"{len(kev_hits)} known-exploited, {len(epss)} EPSS score(s)")
    b.vuln_findings = findings
    unverified = sum(1 for i in b.pkg_info.values() if i["vuln_status"] == "unverified")
    b.say(NAME, "orchestrator", f"{len(findings)} verified-advisory finding(s) across "
                                f"{len({f['package_id'] for f in findings})} package(s); {unverified} package(s) not verifiable.")
    if kev_hits:
        b.say(NAME, "remediation", f"Known-exploited CVEs present: {', '.join(sorted(kev_hits))[:200]}")
    return {"packages_checked": len(eligible), "advisories": len(all_ids), "findings": len(findings),
            "known_exploited": len(kev_hits), "unverified_packages": unverified}
