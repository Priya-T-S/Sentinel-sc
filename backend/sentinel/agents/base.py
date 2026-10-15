"""Agent framework: a shared evidence board, agent contracts, run records and parallel-safe progress.

Design rules (enforced by structure, checked by the Independent Reviewer):
  * Agents that establish FACTS are deterministic (parsers, OSV, registries, Sigstore, static analysis).
  * Each agent writes only its own section of the board and records what it claimed.
  * AI (optional, off by default) may only explain and suggest; it never adds, removes or upgrades a finding.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..intel import IntelContext
from ..models import DependencyGraph
from ..reposource import RepoSource


class ScanCancelled(Exception):
    pass


# (stage key, label, weight, owning agent)
STAGES = [
    ("load", "Reading input safely", 3, "orchestrator"),
    ("parse", "Parsing manifests and lockfiles", 8, "orchestrator"),
    ("graph", "Reconstructing dependency graph", 3, "orchestrator"),
    ("osv", "Matching versions against OSV", 18, "vuln_intel"),
    ("advisories", "Retrieving advisory records", 11, "vuln_intel"),
    ("exploit", "Exploitation evidence (CISA KEV, EPSS)", 4, "vuln_intel"),
    ("registry", "Registry metadata and trust signals", 12, "package_trust"),
    ("provenance", "Verifying build provenance (Sigstore)", 6, "package_trust"),
    ("heuristics", "Supply-chain heuristics and source inspection", 5, "package_trust"),
    ("hygiene", "Secret and CI/CD workflow checks", 2, "package_trust"),
    ("reachability", "Static import, call-site and path analysis", 7, "reachability"),
    ("remediation", "Planning and verifying fixes", 13, "remediation"),
    ("review", "Independent review of claims and evidence", 3, "reviewer"),
    ("finalize", "Scoring, policy decision and report", 2, "orchestrator"),
    ("assist", "AI explanations (optional)", 3, "reviewer"),
]
STAGE_INDEX = {k: i for i, (k, _, _, _) in enumerate(STAGES)}

AGENTS = {
    "orchestrator": {"title": "Orchestrator", "role": "Plans the scan, runs agents in dependency order, keeps the evidence board, produces the final report and policy decision."},
    "vuln_intel": {"title": "Vulnerability Intelligence", "role": "Matches exact versions to advisories (OSV), re-checks affected ranges, merges aliases, adds KEV/EPSS exploitation evidence."},
    "package_trust": {"title": "Package Trust", "role": "Registry history, Sigstore-verified provenance, integrity, typosquat and source-pattern signals, secrets and CI/CD risks."},
    "reachability": {"title": "Reachability Analysis", "role": "Traces dependency paths and blast radius; finds imports and call sites of advisory-named symbols."},
    "remediation": {"title": "Remediation", "role": "Selects the smallest fix for all advisories, re-verifies it on OSV, checks ranges and parent paths, prepares patch candidates."},
    "assistant": {"title": "AI explainer (part of the Reviewer)", "role": "Optional, off by default. Explains reviewed evidence in plain language and suggests investigation steps; a deterministic guard rejects anything that contradicts the verdict."},
    "reviewer": {"title": "Independent Security Reviewer", "role": "Challenges every claim against its evidence, downgrades unsupported ones, flags conflicts; optionally asks an AI to explain (never to decide)."},
}


class Progress:
    """Thread-safe, multi-stage progress (several agents can run at the same time)."""

    def __init__(self, cb: Optional[Callable[[dict], None]], cancel: threading.Event):
        self.cb = cb
        self.cancel = cancel
        self.total = sum(w for _, _, w, _ in STAGES)
        self.frac = {k: 0.0 for k, _, _, _ in STAGES}
        self.stages = [{"key": k, "label": l, "agent": a, "status": "pending", "detail": ""} for k, l, _, a in STAGES]
        self.current: Optional[str] = None
        self.started = time.time()
        self.lock = threading.Lock()

    def _check(self):
        if self.cancel.is_set():
            raise ScanCancelled()

    def start(self, key: str, detail: str = ""):
        self._check()
        with self.lock:
            st = self.stages[STAGE_INDEX[key]]
            st["status"], st["detail"] = "running", detail
            self.current = key
        self._emit()

    def sub(self, key: str, done: int, total: int, detail: str = ""):
        self._check()
        with self.lock:
            self.frac[key] = min(1.0, done / total) if total else 1.0
            if detail:
                self.stages[STAGE_INDEX[key]]["detail"] = detail
        self._emit()

    def done(self, key: str, detail: Optional[str] = None, status: str = "done"):
        with self.lock:
            st = self.stages[STAGE_INDEX[key]]
            st["status"] = status
            if detail is not None:
                st["detail"] = detail
            self.frac[key] = 1.0
        self._emit()

    def _emit(self):
        if not self.cb:
            return
        with self.lock:
            weights = {k: w for k, _, w, _ in STAGES}
            pct = round(100 * sum(weights[k] * f for k, f in self.frac.items()) / self.total, 1)
            payload = {"percent": pct, "stage": self.current, "stages": [dict(s) for s in self.stages],
                       "elapsed": round(time.time() - self.started, 1)}
        self.cb(payload)


@dataclass
class AgentRun:
    agent: str
    status: str = "pending"            # pending | running | done | failed | skipped
    started_at: Optional[float] = None
    duration: Optional[float] = None
    inputs: list = field(default_factory=list)
    outputs: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d.update(AGENTS.get(self.agent, {}))
        if self.duration is not None:
            d["duration"] = round(self.duration, 3)
        return d


@dataclass
class Board:
    """Shared evidence board. Each agent writes its own section; the orchestrator assembles the report."""
    src: RepoSource
    settings: dict
    offline: bool
    cancel: threading.Event
    ictx: IntelContext
    progress: Progress
    graph: DependencyGraph = field(default_factory=DependencyGraph)
    pctx: Any = None
    depth: dict = field(default_factory=dict)
    fatal: Optional[str] = None
    outcomes: list = field(default_factory=list)
    # Vulnerability Intelligence
    vuln_findings: list = field(default_factory=list)
    pkg_info: dict = field(default_factory=dict)
    # Package Trust
    pkg_meta: dict = field(default_factory=dict)
    meta_cache: dict = field(default_factory=dict)
    scorecards: dict = field(default_factory=dict)
    pkg_prov: dict = field(default_factory=dict)
    signal_findings: list = field(default_factory=list)
    # Reachability
    source_index: Any = None
    # Remediation
    plans: list = field(default_factory=list)
    # Reviewer
    review: dict = field(default_factory=dict)
    # Trace
    messages: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def say(self, sender: str, to: str, text: str):
        """Record an inter-agent message (shown in the orchestration trace)."""
        with self.lock:
            if len(self.messages) < 400:
                self.messages.append({"t": round(time.time(), 3), "from": sender, "to": to, "text": text[:300]})
