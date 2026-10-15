"""Pull-request dependency review: what does this change ADD to the supply chain?

Compares a base scan (e.g. main) with a head scan (the PR) and reports only the delta:
  * packages added / removed / version-changed (upgrades vs downgrades), direct vs transitive
  * NEW vulnerabilities and signals (by version-independent fingerprint) and RESOLVED ones
  * risk introductions that deserve a human look even without a CVE: new install scripts,
    new git/URL/local sources, new typosquat-like names, downgrades, large transitive growth
The verdict re-uses the normal deterministic policy, applied to the NEW findings only, so a PR is
not blocked by pre-existing debt it did not introduce (that is the main-branch gate's job).
"""
from __future__ import annotations

import copy
from collections import defaultdict
from typing import Optional

from . import policy as policy_mod
from . import versions
from .models import SEVERITY_ORDER

MARKER = "<!-- sentinel-sc-pr-review -->"

# A PR only adds a small, reviewable delta, so the default bar for NEW risk is higher than for
# existing debt: fail on new high/critical vulnerabilities and on corroborated typosquats.
REVIEW_DEFAULT_OVERRIDES = {
    "fail_on_vulnerability_severity": "high",
    "fail_on_signal_kinds": ["ci_pwn_request", "secret_private_key", "integrity_mismatch", "scope_registry_mismatch",
                             "typosquat", "provenance_invalid"],
}


def review_policy(policy: Optional[dict]) -> dict:
    if policy is not None:
        return policy_mod.validate(policy)
    return policy_mod.validate({**policy_mod.DEFAULT_POLICY, **REVIEW_DEFAULT_OVERRIDES})
GROWTH_WARN = 15  # new transitive packages in one PR that merit attention


def _pkg_index(res: dict) -> dict[tuple, dict]:
    out: dict[tuple, dict] = defaultdict(lambda: {"versions": set(), "direct": False, "items": []})
    for p in res["packages"].values():
        k = (p["ecosystem"], p["name"])
        out[k]["versions"].add(p["version"] or "?")
        out[k]["direct"] = out[k]["direct"] or p["direct"]
        out[k]["items"].append(p)
    return out


def _max_version(eco: str, vs: set) -> Optional[str]:
    vs = [v for v in vs if v and v != "?"]
    if not vs:
        return None
    try:
        return versions.sort_versions(eco, vs)[-1]
    except versions.VersionError:
        return sorted(vs)[-1]


def _brief(f: dict, res: dict) -> dict:
    p = res["packages"].get(f.get("package_id") or "", {})
    adv = f.get("advisory") or {}
    return {"id": f["id"], "fingerprint": f["fingerprint"], "kind": f["kind"], "signal": f.get("signal"),
            "title": f["title"], "severity": f["severity"], "confidence": f.get("confidence"),
            "package": p.get("name") or f.get("file"), "version": p.get("version"), "direct": p.get("direct"),
            "advisory": adv.get("id"), "cves": adv.get("cves", []), "url": adv.get("source_url"),
            "fix": (f.get("remediation") or {}).get("target"),
            "reachability": (f.get("reachability") or {}).get("label"),
            "priority": f["scores"]["priority"], "bucket": f["scores"]["priority_bucket"]}


def review(base: dict, head: dict, policy: Optional[dict] = None) -> dict:
    bi, hi = _pkg_index(base), _pkg_index(head)
    added, removed, changed = [], [], []
    for k, h in hi.items():
        if k not in bi:
            added.append({"ecosystem": k[0], "name": k[1], "versions": sorted(h["versions"]), "direct": h["direct"]})
        elif h["versions"] != bi[k]["versions"]:
            bmax, hmax = _max_version(k[0], bi[k]["versions"]), _max_version(k[0], h["versions"])
            direction = "changed"
            if bmax and hmax:
                try:
                    c = versions.compare(k[0], hmax, bmax)
                    direction = "upgrade" if c > 0 else "downgrade" if c < 0 else "changed"
                except versions.VersionError:
                    pass
            changed.append({"ecosystem": k[0], "name": k[1], "from": sorted(bi[k]["versions"]), "to": sorted(h["versions"]),
                            "direct": h["direct"], "direction": direction,
                            "major": bool(bmax and hmax and versions.is_major_change(k[0], bmax, hmax))})
    for k, b in bi.items():
        if k not in hi:
            removed.append({"ecosystem": k[0], "name": k[1], "versions": sorted(b["versions"]), "direct": b["direct"]})

    bf = {f["fingerprint"]: f for f in base["findings"]}
    hf = {f["fingerprint"]: f for f in head["findings"]}
    new = [hf[k] for k in hf if k not in bf]
    resolved = [bf[k] for k in bf if k not in hf]
    new.sort(key=lambda f: (-(f["scores"]["priority"] or -1), -SEVERITY_ORDER.get(f["severity"], -1)))

    # risk introductions (no CVE needed)
    attention = []
    added_keys = {(a["ecosystem"], a["name"]) for a in added}
    for k in added_keys:
        for p in hi[k]["items"]:
            if p.get("has_install_script"):
                attention.append({"type": "install_script", "package": p["name"], "version": p["version"],
                                  "detail": "New dependency runs code at install time."})
            if p.get("source_type") in ("git", "url", "file"):
                attention.append({"type": "non_registry_source", "package": p["name"], "version": p["version"],
                                  "detail": f"New dependency installed from a {p['source_type']} source, bypassing registry integrity."})
            if p.get("vuln_status") == "unverified":
                attention.append({"type": "unverified", "package": p["name"], "version": p["version"],
                                  "detail": p.get("vuln_status_reason") or "Could not be checked for vulnerabilities."})
    for c in changed:
        if c["direction"] == "downgrade":
            attention.append({"type": "downgrade", "package": c["name"], "version": " -> ".join([", ".join(c["from"]), ", ".join(c["to"])]),
                              "detail": "Version was downgraded; downgrades can silently re-introduce fixed vulnerabilities."})
    new_transitive = sum(1 for a in added if not a["direct"])
    if new_transitive >= GROWTH_WARN:
        attention.append({"type": "dependency_growth", "package": None, "version": None,
                          "detail": f"{new_transitive} new transitive packages arrive with this change."})
    for f in new:
        if f.get("signal") == "typosquat" and f["severity"] in ("high", "medium"):
            p = head["packages"].get(f["package_id"], {})
            attention.append({"type": "typosquat", "package": p.get("name"), "version": p.get("version"), "detail": f["observation"]})

    # verdict: normal policy over NEW findings only (pre-existing debt is the main-branch gate's job)
    delta = copy.copy(head)
    delta["findings"] = new
    delta["coverage"] = dict(head["coverage"])
    new_unavail = sum(1 for k in added_keys for p in hi[k]["items"] if p.get("vuln_status_code") == "intel_unavailable")
    new_noexact = sum(1 for k in added_keys for p in hi[k]["items"] if p.get("vuln_status_code") == "no_exact_version")
    delta["coverage"]["intel_unavailable_packages"] = head["coverage"].get("intel_unavailable_packages", 0)
    delta["coverage"]["no_exact_version_packages"] = new_noexact
    gate = policy_mod.evaluate(delta, review_policy(policy))
    if attention and gate["verdict"] == "pass":
        gate["verdict"] = "warn"

    new_vulns = [f for f in new if f["kind"] == "vulnerability"]
    return {
        "schema": "sentinel-sc/pr-review@1",
        "base": {"source": base["scan"].get("source") or base["scan"]["source_name"], "finished_at": base["scan"]["finished_at"]},
        "head": {"source": head["scan"].get("source") or head["scan"]["source_name"], "finished_at": head["scan"]["finished_at"]},
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed),
                    "downgrades": sum(1 for c in changed if c["direction"] == "downgrade"),
                    "new_vulnerabilities": len(new_vulns), "new_signals": len(new) - len(new_vulns),
                    "resolved": len(resolved), "attention": len(attention), "new_transitive": new_transitive,
                    "new_unverified": new_unavail + new_noexact},
        "packages": {"added": sorted(added, key=lambda a: (not a["direct"], a["name"])), "removed": removed,
                     "changed": sorted(changed, key=lambda c: (c["direction"] != "downgrade", c["name"]))},
        "new_findings": [_brief(f, head) for f in new],
        "resolved_findings": [_brief(f, base) for f in resolved],
        "attention": attention,
        "gate": gate,
        "intel": {p["name"]: p["status"] for p in head["providers"]},
    }


SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜", "unknown": "⬜"}


def _md_escape(s) -> str:
    """Neutralise markdown/HTML in attacker-controlled strings (package names, advisory titles)."""
    t = str(s if s is not None else "")
    for ch in "\\`*_{}[]<>|#!":
        t = t.replace(ch, "\\" + ch)
    return t.replace("\n", " ")[:300]


def to_markdown(rv: dict, max_rows: int = 25) -> str:
    s, g = rv["summary"], rv["gate"]
    icon = {"fail": "❌", "warn": "⚠️", "pass": "✅"}[g["verdict"]]
    out = [MARKER, f"## {icon} SENTINEL-SC dependency review — {g['verdict'].upper()}", ""]
    out.append(f"**{s['added']}** added · **{s['changed']}** changed ({s['downgrades']} downgrade(s)) · **{s['removed']}** removed · "
               f"**{s['new_vulnerabilities']}** new vulnerabilities · **{s['new_signals']}** new signals · "
               f"**{s['resolved']}** resolved")
    out.append("")
    if g["violations"]:
        out.append("### Why this fails")
        grouped: dict = {}
        for v in g["violations"]:
            key = (v["rule"], v.get("package") or v.get("file") or "")
            grouped.setdefault(key, []).append(v)
        for (rule, who), vs in list(grouped.items())[:max_rows]:
            if rule in ("fail_on_vulnerability_severity", "fail_on_known_exploited"):
                sevs = sorted({v.get("severity", "") for v in vs}, key=lambda x: -SEVERITY_ORDER.get(x, -1))
                ids = ", ".join(_md_escape(v.get("advisory")) for v in vs[:4]) + (" …" if len(vs) > 4 else "")
                out.append(f"- `{_md_escape(who)}`: {len(vs)} new {'/'.join(sevs)} vulnerabilit{'y' if len(vs) == 1 else 'ies'} ({ids})")
            else:
                out.append(f"- `{_md_escape(who)}`: {_md_escape(vs[0]['message'])} — rule `{rule}`")
        out.append("")
    vulns = [f for f in rv["new_findings"] if f["kind"] == "vulnerability"]
    sigs = [f for f in rv["new_findings"] if f["kind"] != "vulnerability"]
    if vulns:
        by_pkg: dict = {}
        for f in vulns:
            by_pkg.setdefault((f["package"], f["version"]), []).append(f)
        out.append("### New vulnerabilities introduced by this change")
        out.append("| Package | New advisories | Worst | Fix | Reachability |")
        out.append("|---|---|---|---|---|")
        rows = sorted(by_pkg.items(), key=lambda kv: -max(SEVERITY_ORDER.get(f["severity"], -1) for f in kv[1]))
        for (name, ver), fs in rows[:max_rows]:
            counts = {}
            for f in fs:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            worst = max(fs, key=lambda f: SEVERITY_ORDER.get(f["severity"], -1))["severity"]
            sev_txt = " ".join(f"{SEV_ICON.get(k, '')}{n}" for k, n in sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], -1)))
            fix = next((f["fix"] for f in fs if f.get("fix")), None)
            direct = "" if fs[0].get("direct") else " (transitive)"
            out.append(f"| `{_md_escape(name)}@{_md_escape(ver)}`{direct} | {len(fs)} ({sev_txt}) | {worst} | "
                       f"{_md_escape(fix) if fix else 'no verified fix'} | {_md_escape(fs[0].get('reachability') or '—')} |")
        out.append("")
        out.append("<details><summary>All new advisories</summary>\n")
        for f in vulns[:100]:
            ident = f"[{_md_escape(f['advisory'])}]({f['url']})" if str(f.get("url", "")).startswith("https://") else _md_escape(f["advisory"])
            out.append(f"- {SEV_ICON.get(f['severity'], '')} {ident} `{_md_escape(f['package'])}@{_md_escape(f['version'])}` — {_md_escape(f['title'])}")
        out.append("\n</details>\n")
    if sigs:
        out.append("### New supply-chain signals")
        for f in sigs[:max_rows]:
            who = f"`{_md_escape(f['package'])}@{_md_escape(f['version'])}`" if f.get("version") else f"`{_md_escape(f['package'])}`"
            out.append(f"- {SEV_ICON.get(f['severity'], '')} **{_md_escape(f['title'])}** — {who} (confidence {f.get('confidence')})")
        out.append("")
    if rv["attention"]:
        out.append("### Needs a human look")
        for a in rv["attention"][:max_rows]:
            who = f"`{_md_escape(a['package'])}@{_md_escape(a['version'])}` — " if a.get("package") else ""
            out.append(f"- **{a['type'].replace('_', ' ')}**: {who}{_md_escape(a['detail'])}")
        out.append("")
    pk = rv["packages"]
    if pk["added"] or pk["changed"] or pk["removed"]:
        out.append("<details><summary>Dependency changes</summary>\n")
        out.append("| Change | Package | Versions |")
        out.append("|---|---|---|")
        for a in pk["added"][:max_rows * 2]:
            out.append(f"| ➕ added{' (direct)' if a['direct'] else ''} | `{_md_escape(a['name'])}` | {_md_escape(', '.join(a['versions']))} |")
        for c in pk["changed"][:max_rows * 2]:
            arrow = "⬇️ downgrade" if c["direction"] == "downgrade" else "⬆️ upgrade" if c["direction"] == "upgrade" else "🔁 changed"
            out.append(f"| {arrow}{' (major)' if c['major'] else ''} | `{_md_escape(c['name'])}` | {_md_escape(', '.join(c['from']))} → {_md_escape(', '.join(c['to']))} |")
        for r in pk["removed"][:max_rows * 2]:
            out.append(f"| ➖ removed | `{_md_escape(r['name'])}` | {_md_escape(', '.join(r['versions']))} |")
        out.append("\n</details>\n")
    if rv["resolved_findings"]:
        out.append(f"✅ This change resolves **{len(rv['resolved_findings'])}** existing finding(s).\n")
    degraded = [k for k, v in rv["intel"].items() if v in ("failed", "degraded", "offline")]
    if degraded:
        out.append(f"> ⚠️ Intelligence was not fully available ({', '.join(degraded)}); unverified packages are not treated as clean.\n")
    out.append("<sub>Generated by SENTINEL-SC. Only findings introduced by this change are gated; heuristic signals are evidence for review, not malware verdicts.</sub>")
    return "\n".join(out) + "\n"
