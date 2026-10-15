"""Agent 3 - Package Trust (deterministic).

Registry history and metadata, OpenSSF Scorecard, Sigstore-verified build provenance, typosquat /
integrity / install-script / source-pattern heuristics, repository-level hygiene (lockfiles, pinning,
registries) and secret / CI-CD workflow checks.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .. import provenance as prov
from ..analyzers import heuristics, hygiene
from ..config import LIMITS
from ..intel import registry as reg
from ..models import Package
from .base import Board

NAME = "package_trust"


def run(b: Board) -> dict:
    pr, ictx, graph = b.progress, b.ictx, b.graph
    # ---- registry metadata (direct dependencies first; Remediation fetches anything else it needs)
    pr.start("registry")
    targets = sorted([p for p in graph.packages.values() if p.ecosystem in ("npm", "PyPI") and p.source_type == "registry"],
                     key=lambda p: (not p.direct, p.name))[:LIMITS.max_registry_lookups]

    def fetch(p: Package):
        return p, (reg.npm_metadata(ictx, p.name) if p.ecosystem == "npm" else reg.pypi_metadata(ictx, p.name))
    if ictx.enable_registry:
        done = 0
        with ThreadPoolExecutor(max_workers=6) as pool:
            for p, (meta, origin, ts) in pool.map(fetch, targets):
                b.pkg_meta[p.id] = (meta, origin, ts)
                b.meta_cache[(p.ecosystem, p.name)] = meta
                done += 1
                if done % 4 == 0:
                    pr.sub("registry", done, len(targets), f"{done}/{len(targets)} packages enriched")
    if ictx.enable_scorecard:
        repos = [(p.id, m["repository"]) for p in graph.packages.values()
                 for m in [b.pkg_meta.get(p.id, (None,))[0]] if p.direct and m and m.get("repository") and "github.com" in m["repository"]]
        for pid, repo in repos[:LIMITS.max_scorecard_lookups]:
            b.scorecards[pid] = reg.scorecard(ictx, repo)
    pr.done("registry", f"{len(b.pkg_meta)} registry record(s), {len(b.scorecards)} Scorecard lookup(s)")

    # ---- provenance (Sigstore)
    pr.start("provenance")
    targets = []
    for p in graph.packages.values():
        if p.ecosystem != "npm" or p.source_type != "registry" or not p.version:
            continue
        meta = b.pkg_meta.get(p.id, (None,))[0]
        vmeta = ((meta or {}).get("versions") or {}).get(p.version) if meta else None
        if vmeta is None:
            continue  # registry metadata unknown -> provenance unknown (not "absent")
        if vmeta.get("has_provenance"):
            targets.append(p)
        else:
            b.pkg_prov[p.id] = {"status": "absent", "reason": "No provenance attestation is published for this version."}
    targets.sort(key=lambda p: (not p.direct, p.name))
    for p in targets[prov.MAX_VERIFY:]:
        b.pkg_prov[p.id] = {"status": "unavailable", "reason": f"Not verified: per-scan limit of {prov.MAX_VERIFY} provenance checks reached."}
    batch = targets[:prov.MAX_VERIFY]
    for i, p in enumerate(batch):
        if b.cancel.is_set():
            break
        try:
            b.pkg_prov[p.id] = prov.verify_package(ictx, p, b.pkg_meta.get(p.id, (None,))[0])
        except Exception as exc:  # one malformed attestation must not break the scan
            b.pkg_prov[p.id] = {"status": "unavailable", "reason": f"Verification error: {type(exc).__name__}"}
        pr.sub("provenance", i + 1, len(batch), f"{i + 1}/{len(batch)} attestations verified")
    prov_findings = [f for p in graph.packages.values() if p.id in b.pkg_prov for f in [prov.to_finding(p, b.pkg_prov[p.id])] if f]
    verified = sum(1 for v in b.pkg_prov.values() if v.get("status") == "verified")
    pr.done("provenance", f"{verified} verified, {len(prov_findings)} failed/mismatched")

    # ---- heuristics
    pr.start("heuristics")
    sigs: list[dict] = []
    for i, p in enumerate(graph.packages.values()):
        meta, origin, _ = b.pkg_meta.get(p.id, (None, "unavailable", None))
        for s in heuristics.analyze_package(p, graph, meta, origin, b.src) + heuristics.source_signals(p, b.src):
            s["package_id"] = p.id
            sigs.append(s)
        if i % 50 == 0:
            pr.sub("heuristics", i, len(graph.packages))
    sigs += heuristics.repo_level_findings(b.pctx, graph)
    sigs += prov_findings
    pr.done("heuristics", f"{len(sigs)} signal(s)")

    # ---- secrets & CI/CD
    pr.start("hygiene")
    hyg = hygiene.scan_secrets(b.src) + hygiene.scan_workflows(b.src)
    pr.done("hygiene", f"{len(hyg)} finding(s)")
    b.signal_findings = sigs + hyg
    sus = sum(1 for s in sigs if s["kind"] == "suspicious" and s["severity"] in ("high", "critical"))
    b.say(NAME, "orchestrator", f"{len(b.signal_findings)} trust/hygiene signal(s); {verified} package(s) with verified provenance; "
                                f"{sus} high-severity suspicious signal(s).")
    if prov_findings:
        b.say(NAME, "reviewer", f"{len(prov_findings)} provenance verification failure(s) need attention.")
    return {"registry_records": len(b.pkg_meta), "scorecards": len(b.scorecards), "provenance_verified": verified,
            "provenance_failed": len(prov_findings), "signals": len(sigs), "hygiene": len(hyg)}
