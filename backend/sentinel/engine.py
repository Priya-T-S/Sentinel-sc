"""Scan orchestration: parse -> graph -> intelligence -> heuristics -> reachability -> scoring -> remediation."""
from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Optional

from . import __version__, db, remediation, scoring
from .analyzers import heuristics, hygiene, reachability, vulns
from .intel import IntelContext
from .intel import osv as osv_provider
from .intel import registry as reg
from .models import SEVERITY_ORDER, DependencyGraph, Package
from .parsers import COVERAGE, parse_repository
from .parsers.base import ManifestError, ParseContext
from .reposource import RepoSource

STAGES = [
    ("load", "Reading input safely", 3),
    ("parse", "Parsing manifests and lockfiles", 9),
    ("graph", "Reconstructing dependency graph", 3),
    ("osv", "Matching versions against OSV", 20),
    ("advisories", "Retrieving advisory records", 12),
    ("registry", "Registry metadata, provenance and trust", 16),
    ("heuristics", "Supply-chain heuristics and source inspection", 6),
    ("reachability", "Static import and call-site analysis", 7),
    ("exploit", "Exploitation evidence (CISA KEV, EPSS)", 5),
    ("remediation", "Planning and verifying fixes", 14),
    ("hygiene", "Secret and CI/CD workflow checks", 3),
    ("finalize", "Scoring, policy evaluation and report", 2),
]


class ScanCancelled(Exception):
    pass


class Progress:
    def __init__(self, cb: Optional[Callable[[dict], None]], cancel: threading.Event):
        self.cb = cb
        self.cancel = cancel
        self.done_weight = 0
        self.total = sum(w for _, _, w in STAGES)
        self.stages = [{"key": k, "label": l, "status": "pending", "detail": ""} for k, l, _ in STAGES]
        self.idx = -1
        self.started = time.time()

    def stage(self, key: str, detail: str = ""):
        if self.cancel.is_set():
            raise ScanCancelled()
        if self.idx >= 0:
            self.stages[self.idx]["status"] = "done"
            self.done_weight += STAGES[self.idx][2]
        self.idx = [k for k, _, _ in STAGES].index(key)
        self.stages[self.idx]["status"] = "running"
        self.stages[self.idx]["detail"] = detail
        self._emit(0.0)

    def sub(self, done: int, total: int, detail: str = ""):
        if self.cancel.is_set():
            raise ScanCancelled()
        if detail:
            self.stages[self.idx]["detail"] = detail
        self._emit(done / total if total else 1.0)

    def finish(self):
        if self.idx >= 0:
            self.stages[self.idx]["status"] = "done"
        self.done_weight = self.total
        self._emit(0)

    def _emit(self, frac: float):
        if self.cb:
            cur = STAGES[self.idx][2] * frac if 0 <= self.idx < len(STAGES) else 0
            self.cb({"percent": round(100 * (self.done_weight + cur) / self.total, 1),
                     "stage": STAGES[self.idx][0] if self.idx >= 0 else None, "stages": [dict(s) for s in self.stages],
                     "elapsed": round(time.time() - self.started, 1)})


def _iso(ts: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def _fid(*parts) -> str:
    return "F-" + hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:10]


def run_scan(src: RepoSource, *, offline: bool = False, progress_cb=None, cancel: Optional[threading.Event] = None,
             settings: Optional[dict] = None, scan_id: Optional[str] = None, policy: Optional[dict] = None) -> dict:
    settings = settings or db.get_settings()
    cancel = cancel or threading.Event()
    prog = Progress(progress_cb, cancel)
    t0 = time.time()
    ictx = IntelContext(offline=offline, cancel_event=cancel,
                        enable_registry=settings.get("enable_registry_metadata", True),
                        enable_scorecard=settings.get("enable_scorecard", True),
                        enable_epss_kev=settings.get("enable_epss_kev", True))
    prog.stage("load", f"{src.report.files_seen} file(s) indexed")

    # ------------------------------------------------------------------ parse
    prog.stage("parse")
    graph = DependencyGraph()
    pctx = ParseContext(graph=graph)
    fatal = None
    try:
        parse_repository(src, pctx, progress=lambda p: prog.sub(0, 1, f"parsed {p}"))
    except ManifestError as exc:
        fatal = str(exc)
    outcomes = [o.to_dict() for o in pctx.outcomes]

    prog.stage("graph", f"{len(graph.packages)} packages, {sum(len(v) for v in graph.edges.values())} edges")
    depth = graph.depth_map()

    # ------------------------------------------------------------------ OSV matching
    prog.stage("osv")
    eligible = [p for p in graph.packages.values() if osv_provider.eligible(p)]
    q = osv_provider.query_versions(ictx, [(p.ecosystem, p.name, p.version) for p in eligible],
                                    progress=lambda d, t: prog.sub(d, t, f"{d}/{t} package versions queried"))
    all_ids = sorted({i for r in q.values() for i in (r["ids"] or [])})
    prog.stage("advisories", f"{len(all_ids)} advisory record(s)")
    details = osv_provider.fetch_vulns(ictx, all_ids, progress=lambda d, t: prog.sub(d, t, f"{d}/{t} advisories retrieved"))

    pkg_info: dict[str, dict] = {}
    findings: list[dict] = []
    for p in graph.packages.values():
        info = {"vuln_status": "not_applicable", "vuln_status_code": None, "vuln_status_reason": "", "osv_origin": None,
                "osv_checked_at": None}
        if p in eligible:
            r = q.get((p.ecosystem, p.name, p.version)) or {"ids": None, "origin": "unavailable"}
            info["osv_origin"], info["osv_checked_at"] = r["origin"], _iso(r.get("fetched_at"))
            if r["ids"] is None:
                info["vuln_status"], info["vuln_status_code"] = "unverified", "intel_unavailable"
                info["vuln_status_reason"] = "Vulnerability intelligence unavailable for this package (provider error/offline, no cached data)."
            else:
                info["vuln_status"] = "checked"
                for f in vulns.match_package(p, r["ids"], details, r["origin"], r.get("fetched_at")):
                    findings.append(f)
        elif not p.version:
            info["vuln_status"], info["vuln_status_code"] = "unverified", "no_exact_version"
            info["vuln_status_reason"] = "No exact version (range only / no lockfile): cannot be matched to advisories."
        elif p.source_type in ("file", "git", "url", "workspace"):
            info["vuln_status_reason"] = f"Non-registry source ({p.source_type}); advisory databases key on registry releases."
        else:
            info["vuln_status_reason"] = f"Ecosystem '{p.ecosystem}' not covered by the vulnerability provider."
        pkg_info[p.id] = info

    # ------------------------------------------------------------------ registry metadata
    prog.stage("registry")
    meta_cache: dict = {}
    reg_targets = sorted([p for p in graph.packages.values() if p.ecosystem in ("npm", "PyPI") and p.source_type == "registry"],
                         key=lambda p: (not p.direct, not any(f["package_id"] == p.id for f in findings), p.name))
    from .config import LIMITS
    reg_targets = reg_targets[:LIMITS.max_registry_lookups]
    pkg_meta: dict[str, tuple] = {}
    from concurrent.futures import ThreadPoolExecutor

    def fetch_meta(p: Package):
        if p.ecosystem == "npm":
            return p, reg.npm_metadata(ictx, p.name)
        return p, reg.pypi_metadata(ictx, p.name)
    if ictx.enable_registry:
        done = 0
        with ThreadPoolExecutor(max_workers=6) as pool:
            for p, (meta, origin, ts) in pool.map(fetch_meta, reg_targets):
                pkg_meta[p.id] = (meta, origin, ts)
                meta_cache[(p.ecosystem, p.name)] = meta
                done += 1
                if done % 4 == 0:
                    prog.sub(done, len(reg_targets), f"{done}/{len(reg_targets)} packages enriched")
    # scorecard for direct dependencies with GitHub repos
    scorecards: dict[str, tuple] = {}
    if ictx.enable_scorecard:
        repos = []
        for p in graph.packages.values():
            m = pkg_meta.get(p.id, (None,))[0]
            if p.direct and m and m.get("repository") and "github.com" in m["repository"]:
                repos.append((p.id, m["repository"]))
        for pid, repo in repos[:LIMITS.max_scorecard_lookups]:
            scorecards[pid] = reg.scorecard(ictx, repo)
    prog.sub(1, 1, f"{len(pkg_meta)} registry record(s), {len(scorecards)} Scorecard lookup(s)")

    # ------------------------------------------------------------------ heuristics
    prog.stage("heuristics")
    sig_findings: list[dict] = []
    for i, p in enumerate(graph.packages.values()):
        meta, origin, _ = pkg_meta.get(p.id, (None, "unavailable", None))
        for s in heuristics.analyze_package(p, graph, meta, origin, src) + heuristics.source_signals(p, src):
            s["package_id"] = p.id
            sig_findings.append(s)
        if i % 50 == 0:
            prog.sub(i, len(graph.packages))
    sig_findings += heuristics.repo_level_findings(pctx, graph)

    # ------------------------------------------------------------------ reachability
    prog.stage("reachability")
    idx = reachability.build_index(src, graph)
    prog.sub(1, 2, f"{idx.files_scanned} source file(s) indexed")
    for f in findings:
        p = graph.packages[f["package_id"]]
        f["reachability"] = reachability.assess(idx, graph, p, f["advisory"])

    # ------------------------------------------------------------------ exploitation evidence
    prog.stage("exploit")
    cves = sorted({c for f in findings for c in f["advisory"]["cves"]})
    kev_hits, epss = {}, {}
    kev_available = False
    kev_origin = None
    if cves and ictx.enable_epss_kev and not cancel.is_set():
        cat, kev_origin, kev_ts = reg.kev_catalog(ictx)
        if cat:
            kev_available = True
            for c in cves:
                if c in cat.get("cves", {}):
                    kev_hits[c] = {"cve": c, **cat["cves"][c], "catalog_version": cat.get("catalogVersion"), "origin": kev_origin}
        epss = reg.epss_scores(ictx, cves)

    # ------------------------------------------------------------------ blast radius & ids
    for f in findings:
        p = graph.packages[f["package_id"]]
        f["id"] = _fid("vuln", p.ecosystem, p.name, p.version, f["advisory"]["id"])
        f["fingerprint"] = _fid("vuln", p.ecosystem, p.name, f["advisory"]["id"])
        _attach_paths(f, graph, p, depth)
        kev = next((kev_hits[c] for c in f["advisory"]["cves"] if c in kev_hits), None)
        ep = max((epss[c] for c in f["advisory"]["cves"] if c in epss), key=lambda x: x["epss"], default=None)
        if kev:
            expl_summary = "Listed in CISA KEV: exploited in the wild"
        elif not f["advisory"]["cves"]:
            expl_summary = "No CVE alias, so CISA KEV cannot be checked"
        elif kev_available:
            expl_summary = f"Not listed in CISA KEV ({kev_origin} catalog); absence is not proof of non-exploitation"
        else:
            expl_summary = "Exploitation status not verified (KEV catalog unavailable)"
        f["exploitation"] = {"kev": kev, "epss": ep, "kev_checked": kev_available,
                             "exploit_references": f["advisory"].get("exploit_references", []), "summary": expl_summary}
    for s in sig_findings:
        p = graph.packages.get(s.get("package_id")) if s.get("package_id") else None
        s["id"] = _fid(s["kind"], s["signal"], p.id if p else s.get("file"), s.get("name"), s.get("line"), s.get("observation", "")[:80])
        s["fingerprint"] = _fid(s["kind"], s["signal"], f"{p.ecosystem}:{p.name}" if p else s.get("file"), s.get("name"))
        if p:
            _attach_paths(s, graph, p, depth)

    # ------------------------------------------------------------------ remediation
    prog.stage("remediation")
    by_pkg: dict[str, list[dict]] = {}
    for f in findings:
        by_pkg.setdefault(f["package_id"], []).append(f)
    plans = []
    for i, (pid, fs) in enumerate(sorted(by_pkg.items(), key=lambda kv: -max(SEVERITY_ORDER.get(f["severity"], 0) for f in kv[1]))):
        p = graph.packages[pid]
        reach = max((f["reachability"]["level"] for f in fs), key=lambda l: scoring.REACH_W.get(l, 0))
        plan = remediation.plan_package(ictx, graph, p, fs, src, meta_cache, reach)
        plans.append(plan)
        for f in fs:
            f["remediation"] = {"state": plan["state"], "target": plan.get("target"), "fix_confidence": plan["fix_confidence"],
                                "major_change": plan.get("major_change"), "plan_package": pid}
        prog.sub(i + 1, len(by_pkg), f"{i + 1}/{len(by_pkg)} packages planned")

    # ------------------------------------------------------------------ hygiene
    prog.stage("hygiene")
    hyg = hygiene.scan_secrets(src) + hygiene.scan_workflows(src)
    for h in hyg:
        h["id"] = _fid(h["kind"], h["signal"], h.get("file"), h.get("line"), h["observation"][:60])
        h["fingerprint"] = _fid(h["kind"], h["signal"], h.get("file"), h["title"])
    sig_findings += hyg

    # ------------------------------------------------------------------ scoring & assembly
    prog.stage("finalize")
    plan_by_pkg = {pl["package_id"]: pl for pl in plans}
    for f in findings:
        p = graph.packages[f["package_id"]]
        kev = f["exploitation"]["kev"]
        f["scores"] = scoring.score_vulnerability(f, p.scope, p.version_exact, kev, f["exploitation"]["epss"],
                                                  plan_by_pkg.get(p.id, {}).get("fix_confidence") == "verified")
    for s in sig_findings:
        p = graph.packages.get(s.get("package_id")) if s.get("package_id") else None
        s["scores"] = scoring.score_signal(s, p.scope if p else "runtime")
    all_findings = findings + sig_findings
    all_findings.sort(key=lambda f: (-(f["scores"]["priority"] or -1), -SEVERITY_ORDER.get(f["severity"], -1)))
    # package-level enrichment
    finding_ids_by_pkg: dict[str, list] = {}
    for f in all_findings:
        if f.get("package_id"):
            finding_ids_by_pkg.setdefault(f["package_id"], []).append(f)
    packages_out = {}
    for p in graph.packages.values():
        meta, origin, ts = pkg_meta.get(p.id, (None, "not_requested", None))
        fs = finding_ids_by_pkg.get(p.id, [])
        d = p.to_dict()
        d.update(pkg_info.get(p.id, {}))
        d["depth"] = depth.get(p.id)
        d["dependents"] = len(graph.redges.get(p.id, ())) - sum(1 for r in graph.redges.get(p.id, ()) if r in graph.roots)
        d["dependencies"] = len(graph.edges.get(p.id, {}))
        d["finding_ids"] = [f["id"] for f in fs]
        d["vulnerability_count"] = sum(1 for f in fs if f["kind"] == "vulnerability")
        d["signal_count"] = sum(1 for f in fs if f["kind"] != "vulnerability")
        d["max_severity"] = max((f["severity"] for f in fs), key=lambda s: SEVERITY_ORDER.get(s, -1), default=None)
        d["risk"] = scoring.package_risk(fs)
        d["trust"] = _trust_profile(p, meta, origin, ts, scorecards.get(p.id))
        d["registry"] = _registry_summary(meta, origin, ts, p)
        d["imported_in"] = [{"file": s.file, "line": s.line, "is_test": s.is_test} for s in reachability.imports_for(idx, p)[:10]]
        packages_out[p.id] = d

    providers = ictx.provider_summary()
    unverified = [pid for pid, i in pkg_info.items() if i["vuln_status"] == "unverified"]
    status = "complete"
    if fatal or not graph.packages:
        status = "failed" if not graph.packages else "partial"
    elif unverified or any(o["status"] in ("error", "unsupported", "partial") for o in outcomes) \
            or any(p["status"] in ("degraded", "failed") for p in providers if p["name"] == "osv"):
        status = "partial"
    prog.finish()
    result = {
        "schema": "sentinel-sc/scan-result@1",
        "scan": {"id": scan_id, "source_name": src.name, "engine_version": __version__, "offline": offline,
                 "started_at": _iso(t0), "finished_at": _iso(time.time()), "duration_seconds": round(time.time() - t0, 2),
                 "status": status, "fatal_error": fatal},
        "coverage": {"outcomes": outcomes, "input": src.report.__dict__, "source_index": idx.to_summary(),
                     "unverified_packages": len(unverified),
                     "intel_unavailable_packages": sum(1 for i in pkg_info.values() if i["vuln_status_code"] == "intel_unavailable"),
                     "no_exact_version_packages": sum(1 for i in pkg_info.values() if i["vuln_status_code"] == "no_exact_version"),
                     "matrix": COVERAGE},
        "providers": providers,
        "privacy": {"data_sent": [{"provider": p["label"], "data": p["data_sent"], "calls": p["live_calls"]}
                                  for p in providers if p["live_calls"]],
                    "never_sent": "Source code, file contents, environment variables, secrets, file paths, and repository names."},
        "stats": graph.stats(),
        "graph": graph.to_dict(),
        "packages": packages_out,
        "findings": all_findings,
        "remediation": {"plans": plans, "combined_patch": remediation.combined_patch(plans, src, graph)},
        "progress": {"stages": prog.stages},
    }
    result["summary"] = summarize(result)
    from . import policy as policy_mod
    result["policy"] = policy_mod.evaluate(result, policy or policy_mod.current_policy())
    return result


def _attach_paths(f: dict, graph: DependencyGraph, p: Package, depth: dict):
    paths = graph.paths_to(p.id, limit=25)
    f["paths"] = paths
    roots = graph.affected_roots(p.id)
    f["blast_radius"] = {"roots": len(roots), "root_ids": roots[:20], "dependents": graph.dependents_count(p.id) - len(roots),
                         "direct_dependencies": [graph.packages[x].name for x in graph.direct_ancestors(p.id) if x in graph.packages][:20],
                         "depth": depth.get(p.id), "path_count": len(paths),
                         "path_known": any(graph.edges.get(r, {}).get(p.id, {}).get("relation") != "unknown-path" for r in graph.redges.get(p.id, ()))
                         or any(x not in graph.roots for x in graph.redges.get(p.id, ()))}


def _trust_profile(p: Package, meta: Optional[dict], origin: str, ts, sc) -> dict:
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
    # provenance
    if p.ecosystem == "npm" and vmeta:
        if vmeta.get("has_provenance"):
            add("provenance", "Build provenance", "present", "npm provenance attestation published (presence only; signature not verified locally).", f"npm registry ({origin})")
        else:
            add("provenance", "Build provenance", "absent", "No provenance attestation published for this version (common for older releases).", f"npm registry ({origin})")
        add("signatures", "Registry signature", "present" if vmeta.get("has_signatures") else "absent",
            "npm registry ECDSA signature listed (presence only)." if vmeta.get("has_signatures") else "No registry signature listed.", f"npm registry ({origin})")
    else:
        add("provenance", "Build provenance", "unknown", "Provenance metadata not available for this ecosystem/package.", "-")
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
