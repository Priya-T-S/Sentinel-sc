"""Scan entry point and shared helpers (paths, trust profiles, summaries, what-if). Orchestration lives in sentinel/agents."""
from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from . import remediation, scoring
from .agents.base import STAGES, ScanCancelled  # noqa: F401  (re-exported for jobs/app)
from .analyzers import vulns
from .intel import IntelContext
from .intel import osv as osv_provider
from .intel import registry as reg
from .models import DependencyGraph, Package
from .reposource import RepoSource


def _iso(ts: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def _fid(*parts) -> str:
    return "F-" + hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:10]


def run_scan(src: RepoSource, *, offline: bool = False, progress_cb=None, cancel: Optional[threading.Event] = None,
             settings: Optional[dict] = None, scan_id: Optional[str] = None, policy: Optional[dict] = None) -> dict:
    """Run a full scan. Execution is coordinated by the multi-agent Orchestrator (see sentinel/agents)."""
    from .agents import Orchestrator
    return Orchestrator(src, offline=offline, progress_cb=progress_cb, cancel=cancel, settings=settings,
                        scan_id=scan_id, policy=policy).run()


def _attach_paths(f: dict, graph: DependencyGraph, p: Package, depth: dict):
    paths = graph.paths_to(p.id, limit=25)
    f["paths"] = paths
    roots = graph.affected_roots(p.id)
    f["blast_radius"] = {"roots": len(roots), "root_ids": roots[:20], "dependents": graph.dependents_count(p.id) - len(roots),
                         "direct_dependencies": [graph.packages[x].name for x in graph.direct_ancestors(p.id) if x in graph.packages][:20],
                         "depth": depth.get(p.id), "path_count": len(paths),
                         "path_known": any(graph.edges.get(r, {}).get(p.id, {}).get("relation") != "unknown-path" for r in graph.redges.get(p.id, ()))
                         or any(x not in graph.roots for x in graph.redges.get(p.id, ()))}


def _trust_profile(p: Package, meta: Optional[dict], origin: str, ts, sc, pv: Optional[dict] = None) -> dict:
    vmeta = (meta or {}).get("versions", {}).get(p.version or "", {}) if meta else {}
    items = []

    def add(key, label, status, detail, source):
        items.append({"key": key, "label": label, "status": status, "detail": detail, "source": source})
    # integrity
    if p.integrity:
        reg_int = vmeta.get("integrity")
        if reg_int and p.integrity == reg_int:
            add("integrity", "Integrity", "good", "Lockfile hash matches the registry's published hash.", "lockfile + registry")
        elif reg_int and p.integrity.startswith("sha512-") and reg_int != p.integrity:
            add("integrity", "Integrity", "bad", "Lockfile hash differs from the registry's hash.", "lockfile + registry")
        else:
            add("integrity", "Integrity", "present", f"Hash recorded ({p.integrity.split('-')[0].split(':')[0]}); not compared to registry.", "lockfile")
    elif p.source_type == "registry" and p.version_exact:
        add("integrity", "Integrity", "missing" if p.ecosystem in ("npm", "crates.io", "NuGet") else "unknown",
            "No hash recorded for this version." if p.ecosystem in ("npm", "crates.io", "NuGet") else "Format does not record hashes.", "lockfile")
    else:
        add("integrity", "Integrity", "unknown", "Not applicable or not recorded.", "-")
    # provenance (cryptographically verified when published)
    if pv and pv.get("status") == "verified":
        add("provenance", "Build provenance", "verified", pv["reason"], f"Sigstore (trust root: {pv.get('trust_root')}), Rekor log #{pv.get('rekor_log_index')}")
    elif pv and pv.get("status") in ("invalid", "repo_mismatch"):
        add("provenance", "Build provenance", "bad", pv["reason"], "Sigstore verification")
    elif pv and pv.get("status") == "absent":
        add("provenance", "Build provenance", "absent", "No provenance attestation published for this version (common for older releases).", f"npm registry ({origin})")
    elif pv:
        add("provenance", "Build provenance", "unknown", pv.get("reason") or "Not verified.", "Sigstore verification")
    else:
        add("provenance", "Build provenance", "unknown", "Provenance metadata not available for this ecosystem/package.", "-")
    if p.ecosystem == "npm" and vmeta:
        add("signatures", "Registry signature", "present" if vmeta.get("has_signatures") else "absent",
            "npm registry ECDSA signature listed (presence only)." if vmeta.get("has_signatures") else "No registry signature listed.", f"npm registry ({origin})")
    # maintenance
    if meta:
        pubs = sorted(d.get("published") for d in (meta.get("versions") or {}).values() if d.get("published"))
        last = reg.days_since(pubs[-1]) if pubs else None
        created = reg.days_since(meta.get("created"))
        add("maintenance", "Maintenance", "good" if last is not None and last < 365 else ("warn" if last is not None else "unknown"),
            f"Last release {last:.0f} days ago; {len(meta.get('versions') or {})} versions; first published {created / 365:.1f} years ago."
            if last is not None and created is not None else "Release history unavailable.", f"registry ({origin})")
        add("repository", "Source repository", "present" if meta.get("repository") else "absent",
            meta.get("repository") or "No repository URL declared.", f"registry ({origin})")
        add("maintainers", "Maintainers", "info", f"{len(meta.get('maintainers') or [])} listed maintainer account(s).", f"registry ({origin})")
    else:
        add("maintenance", "Maintenance", "unknown", "Registry metadata not retrieved for this package.", "-")
    # install scripts
    scripts = vmeta.get("install_scripts") if vmeta else None
    if p.has_install_script or scripts:
        add("install_scripts", "Install scripts", "warn", ", ".join(scripts.keys()) if scripts else "hasInstallScript", "lockfile/registry")
    elif p.has_install_script is False or vmeta:
        add("install_scripts", "Install scripts", "good", "No install-time scripts declared.", "lockfile/registry")
    # scorecard
    if sc and sc[0] and sc[0].get("score") is not None:
        val = sc[0]["score"]
        add("scorecard", "OpenSSF Scorecard", "good" if val >= 7 else "warn" if val >= 4 else "bad",
            f"{val}/10 (as of {str(sc[0].get('date'))[:10]})", f"api.securityscorecards.dev ({sc[1]})")
    return {"items": items, "scorecard": sc[0] if sc and sc[0] else None}


def _registry_summary(meta: Optional[dict], origin: str, ts, p: Package) -> Optional[dict]:
    if not meta:
        return {"available": False, "origin": origin}
    vmeta = (meta.get("versions") or {}).get(p.version or "", {})
    latest = (meta.get("dist_tags") or {}).get("latest") or meta.get("latest")
    hist = sorted(((v, d.get("published")) for v, d in (meta.get("versions") or {}).items() if d.get("published")),
                  key=lambda x: x[1])[-15:]
    return {"available": True, "origin": origin, "retrieved_at": _iso(ts), "created": meta.get("created"),
            "latest": latest, "published": vmeta.get("published"), "license": vmeta.get("license") or meta.get("license"),
            "description": meta.get("description"), "repository": meta.get("repository"),
            "maintainers": (meta.get("maintainers") or [])[:10], "deprecated": vmeta.get("deprecated"),
            "version_count": len(meta.get("versions") or {}), "recent_versions": [{"version": v, "published": t} for v, t in reversed(hist)]}


def summarize(result: dict) -> dict:
    fs = result["findings"]
    vulns_ = [f for f in fs if f["kind"] == "vulnerability"]
    sev = Counter(f["severity"] for f in vulns_)
    kinds = Counter(f["kind"] for f in fs)
    pk = result["packages"]
    vulnerable_pkgs = {f["package_id"] for f in vulns_}
    by_eco: dict[str, dict] = {}
    for p in pk.values():
        e = by_eco.setdefault(p["ecosystem"], {"packages": 0, "vulnerable": 0, "findings": 0, "unverified": 0})
        e["packages"] += 1
        e["vulnerable"] += 1 if p["id"] in vulnerable_pkgs else 0
        e["findings"] += p["vulnerability_count"]
        e["unverified"] += 1 if p["vuln_status"] == "unverified" else 0
    reach = Counter(f["reachability"]["level"] for f in vulns_)
    prios = Counter(f["scores"]["priority_bucket"] for f in fs)
    top = [{"id": f["id"], "title": f["title"], "kind": f["kind"], "severity": f["severity"],
            "package_id": f.get("package_id"), "priority": f["scores"]["priority"], "bucket": f["scores"]["priority_bucket"],
            "remediation": (f.get("remediation") or {}).get("state")} for f in fs[:8]]
    osv = next((p for p in result["providers"] if p["name"] == "osv"), {})
    plans = result["remediation"]["plans"]
    return {
        "status": result["scan"]["status"],
        "packages": result["stats"]["packages"], "direct": result["stats"]["direct"], "transitive": result["stats"]["transitive"],
        "components": result["stats"]["roots"],
        "vulnerabilities": len(vulns_), "vulnerable_packages": len(vulnerable_pkgs),
        "verified_vulnerabilities": sum(1 for f in vulns_ if f["verified"]),
        "severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "unknown")},
        "suspicious_signals": kinds.get("suspicious", 0), "integrity_signals": kinds.get("integrity", 0),
        "maintenance_signals": kinds.get("maintenance", 0), "hygiene_findings": kinds.get("hygiene", 0),
        "secret_findings": kinds.get("secret", 0), "ci_findings": kinds.get("ci", 0),
        "by_kind": dict(kinds), "by_ecosystem": by_eco, "reachability": dict(reach), "priority_buckets": dict(prios),
        "unverified_packages": result["coverage"]["unverified_packages"],
        "known_exploited": sum(1 for f in vulns_ if f["exploitation"]["kev"]),
        "provenance": {k: sum(1 for p in pk.values() if (p.get("provenance") or {}).get("status") == k)
                       for k in ("verified", "invalid", "repo_mismatch", "absent", "unsupported", "unavailable")},
        "fixable": sum(1 for p in plans if p.get("target")),
        "fix_verified": sum(1 for p in plans if p.get("fix_confidence") == "verified"),
        "max_priority": fs[0]["scores"]["priority"] if fs else None,
        "top_priorities": top,
        "data_freshness": {"osv_status": osv.get("status"), "oldest": _iso(osv.get("oldest_data")), "newest": _iso(osv.get("newest_data")),
                           "origins": {k: osv.get(k, 0) for k in ("live_calls", "cache_hits", "stale_hits", "fixture_hits", "misses")}},
    }


# --------------------------------------------------------------------------- what-if

def whatif(result: dict, changes: Optional[dict] = None, offline: bool = False) -> dict:
    """Simulate upgrading packages to new versions WITHOUT modifying the repository.

    Re-queries OSV for each proposed version and re-scores. Limitations (stated in output):
    transitive dependencies of an upgraded package are not re-resolved.
    """
    ictx = IntelContext(offline=offline)
    if changes is None:
        changes = remediation.simulation_changes(result["remediation"]["plans"], result["packages"])
    before = [f for f in result["findings"] if f["kind"] == "vulnerability"]
    pk = result["packages"]
    items = []
    for pid, ver in changes.items():
        p = pk.get(pid)
        if not p or not isinstance(ver, str) or len(ver) > 64:
            continue
        items.append((p["ecosystem"], p["name"], ver.strip()))
    q = osv_provider.query_versions(ictx, items)
    ids = sorted({i for r in q.values() for i in (r["ids"] or [])})
    det = osv_provider.fetch_vulns(ictx, ids)
    after: list[dict] = [f for f in before if f["package_id"] not in changes]
    per_pkg = []
    unverified = []
    for pid, ver in changes.items():
        p = pk.get(pid)
        if not p:
            continue
        r = q.get((p["ecosystem"], p["name"], ver.strip()), {"ids": None})
        old = [f for f in before if f["package_id"] == pid]
        if r["ids"] is None:
            unverified.append(pid)
            per_pkg.append({"package_id": pid, "name": p["name"], "from": p["version"], "to": ver, "before": len(old),
                            "after": None, "status": "not_verified"})
            after.extend(old)
            continue
        npkg = Package(ecosystem=p["ecosystem"], name=p["name"], version=ver, source_file=p["source_file"],
                       version_exact=True, direct=p["direct"], scope=p["scope"])
        newf = vulns.match_package(npkg, r["ids"], det, r["origin"], r.get("fetched_at"))
        reach_by_adv = {f["advisory"]["id"]: f["reachability"] for f in old}
        default_reach = old[0]["reachability"] if old else {"level": "unknown", "label": "Unknown"}
        for f in newf:
            f["reachability"] = reach_by_adv.get(f["advisory"]["id"], default_reach)
            f["paths"] = old[0]["paths"] if old else []
            f["blast_radius"] = old[0].get("blast_radius", {}) if old else {}
            f["scores"] = scoring.score_vulnerability(f, p["scope"], True, None, None, False)
            f["id"] = _fid("vuln", p["ecosystem"], p["name"], ver, f["advisory"]["id"])
            f["package_id"] = npkg.id
        after.extend(newf)
        per_pkg.append({"package_id": pid, "name": p["name"], "from": p["version"], "to": ver, "before": len(old),
                        "after": len(newf), "status": "verified" if r["origin"] in ("live", "cache") else r["origin"],
                        "remaining": [f["advisory"]["id"] for f in newf]})

    def agg(fs):
        sev = Counter(f["severity"] for f in fs)
        pr = [f["scores"]["priority"] for f in fs if f["scores"]["priority"] is not None]
        return {"vulnerabilities": len(fs), "severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "unknown")},
                "max_priority": max(pr) if pr else 0, "total_exposure": round(sum(f["scores"]["exposure"] or 0 for f in fs), 1),
                "p1": sum(1 for f in fs if f["scores"]["priority_bucket"] == "P1")}
    return {
        "label": "SIMULATED - proposed changes have not been applied or rescanned",
        "changes": per_pkg,
        "before": agg(before), "after": agg(after),
        "resolved": [{"id": f["id"], "advisory": f["advisory"]["id"], "package": pk[f["package_id"]]["name"]}
                     for f in before if f["package_id"] in changes and f["package_id"] not in unverified],
        "remaining": [{"advisory": f["advisory"]["id"], "package_id": f["package_id"], "severity": f["severity"]} for f in after],
        "unverified_changes": unverified,
        "limitations": [
            "Only the changed packages are re-evaluated; their own transitive dependencies are not re-resolved.",
            "Compatibility of the new versions with your code is not tested - run your test suite after applying.",
            "Heuristic and hygiene findings are unchanged by version simulation.",
        ],
        "generated_at": _iso(time.time()),
    }
