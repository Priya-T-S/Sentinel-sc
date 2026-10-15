"""Optional AI explanations for the Independent Security Reviewer (off by default).

What the AI may do: explain findings in plain language, suggest investigation steps, and comment on
conflicts the deterministic reviewer flagged. What it may NOT do: add, remove, re-score or re-classify
findings, mark anything safe, or change the policy decision. Its output is stored separately
(result["ai"], finding["ai_explanation"]) and passes a deterministic guard first.

Data minimisation: only evidence the deterministic agents already produced is sent (package names and
versions, advisory text, reachability levels, dependency paths, fix candidates). Source-code snippets
are sent only if the user enables `ai_share_code_snippets`. Secrets are never included.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Optional

from .base import Board

MODEL = "claude-opus-5-5"
MAX_FINDINGS = 8
PRICE_IN, PRICE_OUT = 4.00, 20.00   # USD per 1M tokens (claude-opus-5-5)

SYSTEM = """You are the explanation assistant inside SENTINEL-SC, a software supply-chain scanner.
Deterministic agents have already established every fact you receive (advisory matches from OSV,
dependency paths from lockfiles, static reachability levels, OSV-verified fix candidates, Sigstore
provenance results). Your job is ONLY to help a developer understand and act on that evidence.

Rules:
- Use only the evidence in the user message. Do not introduce CVEs, versions, functions, exploits or
  facts that are not in it. If something is unknown, say it is unknown.
- Never state or imply that a package, finding or version is safe, a false positive, or ignorable.
  Never contradict the deterministic severity, verification status, reachability level or fix status.
- Reachability levels are static evidence, not proof of exploitability; keep that distinction.
- Investigation steps must be concrete actions a developer can take in their own code or pipeline.
- Cite the finding_id you are explaining, and in cited_facts quote short phrases from the evidence.
- Plain, direct language for a developer who is not a security specialist."""

SCHEMA = {
    "type": "object",
    "properties": {
        "overall_summary": {"type": "string"},
        "explanations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "plain_explanation": {"type": "string"},
                    "why_it_matters_here": {"type": "string"},
                    "investigation_steps": {"type": "array", "items": {"type": "string"}},
                    "cited_facts": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["finding_id", "plain_explanation", "why_it_matters_here", "investigation_steps", "cited_facts"],
                "additionalProperties": False,
            },
        },
        "conflict_notes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"conflict_index": {"type": "integer"}, "note": {"type": "string"},
                               "next_steps": {"type": "array", "items": {"type": "string"}}},
                "required": ["conflict_index", "note", "next_steps"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["overall_summary", "explanations", "conflict_notes"],
    "additionalProperties": False,
}

# Phrases the AI must not use: they would override the deterministic verdict.
_FORBIDDEN = re.compile(r"\b(false positive|safe to (ignore|use|deploy)|not (actually )?vulnerable|no (real )?risk|can be ignored|"
                        r"is safe|are safe|not exploitable|harmless)\b", re.I)


def _enabled(b: Board) -> tuple[bool, str]:
    s = b.settings
    if not s.get("ai_assistance"):
        return False, "AI assistance is turned off (Settings -> Privacy)."
    if b.offline:
        return False, "Offline mode: no AI requests are made."
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, "The 'anthropic' package is not installed."
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_PROFILE")):
        # The SDK can also resolve an `ant auth login` profile; we still require an explicit signal so the
        # feature never sends data just because a credential happens to exist on the machine.
        return False, "No Anthropic credential configured (set ANTHROPIC_API_KEY)."
    return True, ""


def build_evidence(result: dict, share_snippets: bool) -> dict:
    pk = result["packages"]
    picked = [f for f in result["findings"] if f["kind"] in ("vulnerability", "suspicious", "integrity", "ci")][:MAX_FINDINGS]
    items = []
    for f in picked:
        p = pk.get(f.get("package_id") or "", {})
        adv = f.get("advisory") or {}
        reach = f.get("reachability") or {}
        ev = {
            "finding_id": f["id"], "kind": f["kind"], "title": f["title"], "severity": f["severity"],
            "verified_by_deterministic_agents": f.get("verified", False), "confidence": f.get("confidence"),
            "package": f"{p.get('name')}@{p.get('version')}" if p else f.get("file"),
            "direct_dependency": p.get("direct"), "scope": p.get("scope"),
            "priority": f["scores"].get("priority_bucket"),
            "dependency_paths": [" -> ".join("application" if x.startswith("root:") else
                                             f"{pk.get(x, {}).get('name', x)}@{pk.get(x, {}).get('version', '?')}" for x in path)
                                 for path in (f.get("paths") or [])[:2]],
            "reachability": {"level": reach.get("level"), "explanation": reach.get("explanation"), "still_needed": reach.get("needed")},
            "remediation": f.get("remediation"),
        }
        if adv:
            ev["advisory"] = {"id": adv.get("id"), "aliases": adv.get("aliases", [])[:6], "summary": adv.get("summary"),
                              "details_excerpt": (adv.get("details") or "")[:1200], "affected_ranges": adv.get("affected_ranges"),
                              "fixed_versions": adv.get("fixed_versions"), "cwes": adv.get("cwes")}
            ev["exploitation"] = (f.get("exploitation") or {}).get("summary")
        else:
            ev["observation"] = f.get("observation")
            ev["explanation"] = f.get("explanation")
        if share_snippets:
            ev["call_sites"] = [{"file": e.get("file"), "line": e.get("line"), "code": e.get("snippet")}
                                for e in reach.get("evidence", []) if e.get("kind") == "call"][:3]
        else:
            ev["call_sites"] = [{"file": e.get("file"), "line": e.get("line")} for e in reach.get("evidence", []) if e.get("kind") == "call"][:3]
        items.append(ev)
    conflicts = [{"conflict_index": i, **{k: c[k] for k in ("type", "package", "detail", "suggestion")}}
                 for i, c in enumerate((result.get("review") or {}).get("conflicts", [])[:10])]
    return {"findings": items, "reviewer_conflicts": conflicts}


def guard(output: dict, evidence: dict) -> tuple[dict, list[dict]]:
    """Deterministic validation of the AI output. Returns (accepted_output, rejections)."""
    rejected = []
    valid_ids = {f["finding_id"] for f in evidence["findings"]}
    accepted = []
    for e in output.get("explanations") or []:
        fid = e.get("finding_id")
        text = " ".join([e.get("plain_explanation", ""), e.get("why_it_matters_here", ""), *e.get("investigation_steps", [])])
        if fid not in valid_ids:
            rejected.append({"finding_id": fid, "reason": "refers to a finding that was not provided"})
            continue
        m = _FORBIDDEN.search(text)
        if m:
            rejected.append({"finding_id": fid, "reason": f"contradicts the deterministic verdict ('{m.group(0)}')"})
            continue
        accepted.append({k: e[k] for k in ("finding_id", "plain_explanation", "why_it_matters_here", "investigation_steps", "cited_facts")})
    n_conf = len(evidence["reviewer_conflicts"])
    notes = []
    for c in output.get("conflict_notes") or []:
        if not isinstance(c.get("conflict_index"), int) or not 0 <= c["conflict_index"] < n_conf:
            rejected.append({"conflict_index": c.get("conflict_index"), "reason": "unknown conflict"})
            continue
        if _FORBIDDEN.search(c.get("note", "")):
            rejected.append({"conflict_index": c["conflict_index"], "reason": "contradicts the deterministic verdict"})
            continue
        notes.append(c)
    summary = output.get("overall_summary", "")
    if _FORBIDDEN.search(summary):
        rejected.append({"field": "overall_summary", "reason": "contradicts the deterministic verdict"})
        summary = ""
    return {"overall_summary": summary, "explanations": accepted, "conflict_notes": notes}, rejected


def call_claude(evidence: dict, client=None) -> tuple[Optional[dict], dict]:
    """One structured-output request. Returns (parsed_json | None, meta)."""
    import anthropic
    client = client or anthropic.Anthropic(timeout=120.0, max_retries=2)
    meta: dict[str, Any] = {"model": MODEL}
    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=16000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        thinking={"type": "adaptive"},
        output_config={"effort": "medium", "format": {"type": "json_schema", "schema": SCHEMA}},
        system=SYSTEM,
        messages=[{"role": "user", "content": "Evidence (JSON):\n" + json.dumps(evidence, ensure_ascii=False)}],
    )
    meta["served_by"] = getattr(response, "model", MODEL)
    meta["stop_reason"] = response.stop_reason
    usage = getattr(response, "usage", None)
    if usage is not None:
        meta["input_tokens"] = getattr(usage, "input_tokens", None)
        meta["output_tokens"] = getattr(usage, "output_tokens", None)
        if meta["input_tokens"] is not None and meta["output_tokens"] is not None:
            meta["estimated_cost_usd"] = round(meta["input_tokens"] * PRICE_IN / 1e6 + meta["output_tokens"] * PRICE_OUT / 1e6, 4)
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        meta["refusal_category"] = getattr(details, "category", None) if details else None
        return None, meta
    text = next((blk.text for blk in response.content if getattr(blk, "type", None) == "text"), None)
    if text is None:
        return None, meta
    return json.loads(text), meta


def run(b: Board, result: dict, client=None) -> dict:
    pr = b.progress
    ok, why = _enabled(b) if client is None else (True, "")
    if not ok:
        pr.done("assist", why, status="skipped")
        result["ai"] = {"enabled": False, "reason": why}
        return {"enabled": False}
    pr.start("assist", f"asking {MODEL} to explain the top findings")
    evidence = build_evidence(result, bool(b.settings.get("ai_share_code_snippets")))
    t0 = time.time()
    try:
        raw, meta = call_claude(evidence, client)
    except Exception as exc:  # AI is optional: failures never affect the scan
        pr.done("assist", "AI request failed", status="failed")
        result["ai"] = {"enabled": True, "status": "error", "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                        "model": MODEL}
        return {"enabled": True, "status": "error"}
    meta["seconds"] = round(time.time() - t0, 1)
    if raw is None:
        pr.done("assist", "AI declined or returned no content", status="done")
        result["ai"] = {"enabled": True, "status": "declined", **meta}
        return {"enabled": True, "status": "declined"}
    accepted, rejected = guard(raw, evidence)
    by_id = {e["finding_id"]: e for e in accepted["explanations"]}
    for f in result["findings"]:
        if f["id"] in by_id:
            f["ai_explanation"] = {**by_id[f["id"]], "model": meta.get("served_by", MODEL),
                                   "label": "AI-generated explanation of deterministic evidence - not a source of truth"}
    result["ai"] = {"enabled": True, "status": "ok", **meta, "summary": accepted["overall_summary"],
                    "explained": len(accepted["explanations"]), "conflict_notes": accepted["conflict_notes"],
                    "guard_rejections": rejected, "shared_code_snippets": bool(b.settings.get("ai_share_code_snippets")),
                    "data_sent": "Finding evidence for the top findings (package names/versions, advisory text, paths, reachability "
                                 "levels, fix candidates" + (", call-site code lines" if b.settings.get("ai_share_code_snippets") else "") + ")."}
    b.say("reviewer", "orchestrator", f"AI explained {len(accepted['explanations'])} finding(s); guard rejected {len(rejected)} item(s).")
    pr.done("assist", f"{len(accepted['explanations'])} explanation(s), {len(rejected)} rejected by guard")
    return {"enabled": True, "status": "ok", "explained": len(accepted["explanations"]), "rejected": len(rejected)}
