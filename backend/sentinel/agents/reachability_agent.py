"""Agent 4 - Reachability Analysis (deterministic).

Builds the source import index, assesses static reachability for every vulnerability, and attaches
dependency paths and blast radius to every package-level finding.
"""
from __future__ import annotations

from ..analyzers import reachability
from .base import Board

NAME = "reachability"


def run(b: Board) -> dict:
    from ..engine import _attach_paths, _fid
    pr = b.progress
    pr.start("reachability")
    b.source_index = idx = reachability.build_index(b.src, b.graph)
    pr.sub("reachability", 1, 3, f"{idx.files_scanned} source file(s) indexed")
    levels: dict[str, int] = {}
    for f in b.vuln_findings:
        p = b.graph.packages[f["package_id"]]
        f["reachability"] = reachability.assess(idx, b.graph, p, f["advisory"])
        levels[f["reachability"]["level"]] = levels.get(f["reachability"]["level"], 0) + 1
        f["id"] = _fid("vuln", p.ecosystem, p.name, p.version, f["advisory"]["id"])
        f["fingerprint"] = _fid("vuln", p.ecosystem, p.name, f["advisory"]["id"])
        _attach_paths(f, b.graph, p, b.depth)
    pr.sub("reachability", 2, 3, "paths and blast radius attached")
    for s in b.signal_findings:
        p = b.graph.packages.get(s.get("package_id")) if s.get("package_id") else None
        s["id"] = _fid(s["kind"], s["signal"], p.id if p else s.get("file"), s.get("name"), s.get("line"), s.get("observation", "")[:80])
        s["fingerprint"] = _fid(s["kind"], s["signal"], f"{p.ecosystem}:{p.name}" if p else s.get("file"), s.get("name"))
        if p:
            _attach_paths(s, b.graph, p, b.depth)
    pr.done("reachability", f"{levels.get('symbol_call', 0)} call-site, {levels.get('imported', 0)} imported")
    if levels.get("symbol_call"):
        b.say(NAME, "remediation", f"{levels['symbol_call']} vulnerability(ies) have static call-site evidence: prioritise them.")
    b.say(NAME, "orchestrator", f"Indexed {idx.files_scanned} source file(s); reachability levels: {levels or 'none'}.")
    return {"source_files": idx.files_scanned, "languages": idx.languages, "levels": levels}
