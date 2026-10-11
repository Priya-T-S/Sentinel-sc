"""Self-contained HTML report. Every dynamic value is HTML-escaped (context-aware output encoding)."""
from __future__ import annotations

import html
from typing import Any

SEV_COLOR = {"critical": "#ff4d6d", "high": "#ff8c42", "medium": "#f5c542", "low": "#5cc8ff", "info": "#9aa4b2", "unknown": "#9aa4b2"}


def e(x: Any) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def _url(u: str) -> str:
    return e(u) if isinstance(u, str) and u.startswith(("https://", "http://")) else "#"


def render_html(result: dict) -> str:
    s = result["summary"]
    pk = result["packages"]
    scan = result["scan"]
    pol = result.get("policy", {})
    rows = []
    for f in [x for x in result["findings"] if x["kind"] == "vulnerability"]:
        p = pk.get(f["package_id"], {})
        adv = f["advisory"]
        path = " → ".join(_label(n, result) for n in (f.get("paths") or [[]])[0])
        rows.append(f"""<tr><td><span class="sev" style="background:{SEV_COLOR.get(f['severity'], '#999')}">{e(f['severity'])}</span></td>
<td><a href="{_url(adv['source_url'])}" rel="noopener noreferrer">{e(adv['id'])}</a><div class="muted">{e(', '.join(a for a in adv['aliases'] if a.startswith('CVE-')))}</div></td>
<td><b>{e(p.get('name'))}</b>@{e(p.get('version'))}<div class="muted">{'direct' if p.get('direct') else 'transitive'} · {e(p.get('scope'))}</div></td>
<td>{e(f['title'])}<div class="muted">Affected: {e('; '.join(adv['affected_ranges'][:2]))}</div></td>
<td class="mono small">{e(path)}</td><td>{e(f['reachability']['label'])}</td>
<td>{e(f['scores']['priority_bucket'])} ({e(f['scores']['priority'])})</td>
<td>{e((f.get('remediation') or {}).get('target') or '—')}<div class="muted">{e((f.get('remediation') or {}).get('state'))} · {e((f.get('remediation') or {}).get('fix_confidence'))}</div></td></tr>""")
    sig_rows = []
    for f in [x for x in result["findings"] if x["kind"] != "vulnerability"][:300]:
        p = pk.get(f.get("package_id") or "", {})
        sig_rows.append(f"""<tr><td><span class="sev" style="background:{SEV_COLOR.get(f['severity'], '#999')}">{e(f['severity'])}</span></td>
<td>{e(f['kind'])}</td><td>{e(f['title'])}</td><td>{e(p.get('name') or f.get('file') or '')}</td><td>{e(f['observation'])}</td><td>{e(f['confidence'])}</td></tr>""")
    plans = []
    for pl in result["remediation"]["plans"]:
        patch = (pl.get("patch") or {}).get("diff")
        plans.append(f"""<div class="card"><h3>{e(pl['package'])} {e(pl['installed'])} → {e(pl.get('target') or 'no verified fix')}</h3>
<p>State: <b>{e(pl['state'])}</b> · Fix confidence: <b>{e(pl['fix_confidence'])}</b> · Major change: {e(pl.get('major_change'))}</p>
<ul>{''.join(f"<li><b>{e(a['step'])}</b>: <code>{e(a['command'])}</code> — {e(a['why'])}</li>" for a in pl.get('actions', []))}</ul>
<ul>{''.join(f"<li>{e(c['check'])}: {e(c['result'])} — {e(c['detail'])}</li>" for c in pl.get('compatibility', []))}</ul>
{f'<pre>{e(patch)}</pre>' if patch else ''}</div>""")
    prov = "".join(f"<tr><td>{e(p['label'])}</td><td>{e(p['status'])}</td><td>{e(p['live_calls'])}</td><td>{e(p['cache_hits'])}</td>"
                   f"<td>{e(p['stale_hits'] + p['fixture_hits'])}</td><td>{e(p['misses'])}</td><td>{e('; '.join(p['errors']))}</td></tr>"
                   for p in result["providers"])
    cov = "".join(f"<tr><td class='mono'>{e(o['file'])}</td><td>{e(o['parser'])}</td><td>{e(o['status'])}</td><td>{e(o['packages'])}</td>"
                  f"<td>{e(o['message'])} {e(' '.join(o.get('limitations', [])))}</td></tr>" for o in result["coverage"]["outcomes"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>SENTINEL-SC report — {e(scan['source_name'])}</title>
<style>body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;background:#0b0f17;color:#dbe2ee;margin:0;padding:24px}}h1,h2,h3{{color:#fff}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border-bottom:1px solid #222b3a;padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:#8b98ad;font-weight:600}}.sev{{padding:2px 8px;border-radius:10px;color:#111;font-weight:700;font-size:12px}}.muted{{color:#8b98ad;font-size:12px}}
.mono{{font-family:ui-monospace,Consolas,monospace}}.small{{font-size:12px}}.card{{background:#121826;border:1px solid #222b3a;border-radius:8px;padding:12px 16px;margin:12px 0}}
pre{{background:#070a10;padding:10px;overflow:auto;border-radius:6px}}a{{color:#6cb6ff}}.kpi{{display:inline-block;margin-right:24px}}.kpi b{{font-size:22px;display:block;color:#fff}}</style></head><body>
<h1>SENTINEL-SC supply-chain report</h1>
<p class="muted">Source: {e(scan['source_name'])} · Scan {e(scan['id'])} · {e(scan['finished_at'])} · Status: {e(scan['status'])} · Engine {e(scan['engine_version'])}{' · OFFLINE (cached/fixture intelligence)' if scan.get('offline') else ''}</p>
<div class="card"><span class="kpi"><b>{e(s['packages'])}</b>packages ({e(s['direct'])} direct)</span><span class="kpi"><b>{e(s['vulnerabilities'])}</b>vulnerabilities in {e(s['vulnerable_packages'])} packages</span>
<span class="kpi"><b>{e(s['severity']['critical'])}/{e(s['severity']['high'])}/{e(s['severity']['medium'])}/{e(s['severity']['low'])}</b>crit/high/med/low</span>
<span class="kpi"><b>{e(s['suspicious_signals'])}</b>suspicious signals</span><span class="kpi"><b>{e(s['unverified_packages'])}</b>not verified</span>
<span class="kpi"><b>{e(pol.get('verdict', 'n/a')).upper()}</b>policy gate</span></div>
<h2>Verified vulnerabilities</h2><table><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Summary</th><th>Path</th><th>Reachability</th><th>Priority</th><th>Fix</th></tr>{''.join(rows) or '<tr><td colspan=8>None</td></tr>'}</table>
<h2>Supply-chain, integrity and hygiene signals</h2><p class="muted">Heuristic signals are evidence for review, not confirmed compromise.</p>
<table><tr><th>Severity</th><th>Kind</th><th>Signal</th><th>Subject</th><th>Observation</th><th>Confidence</th></tr>{''.join(sig_rows) or '<tr><td colspan=6>None</td></tr>'}</table>
<h2>Remediation plan</h2>{''.join(plans) or '<p>No actionable vulnerabilities.</p>'}
<h2>Intelligence providers</h2><table><tr><th>Provider</th><th>Status</th><th>Live</th><th>Cache</th><th>Stale/fixture</th><th>Unavailable</th><th>Errors</th></tr>{prov}</table>
<h2>Coverage</h2><table><tr><th>File</th><th>Parser</th><th>Status</th><th>Packages</th><th>Notes</th></tr>{cov}</table>
<p class="muted">Generated by SENTINEL-SC. Scores are explained in the JSON report (findings[].scores.factors). Reachability levels describe static evidence only; no exploit was executed.</p>
</body></html>"""


def _label(node_id: str, result: dict) -> str:
    p = result["packages"].get(node_id)
    if p:
        return f"{p['name']}@{p['version']}"
    for n in result["graph"]["nodes"]:
        if n["id"] == node_id:
            return n.get("name") or node_id
    return node_id
