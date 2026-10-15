import { AlertOctagon, CheckCircle2, CircleHelp, FileCode2, Link2, Scale, ShieldAlert, ShieldCheck, Sparkles, Wrench } from 'lucide-react'
import { useState } from 'react'
import { useApi } from '../hooks'
import { Link } from '../router'
import { labelFor, useScan } from '../state'
import type { Finding, PackageInfo, Plan } from '../types'
import {
  Callout, CopyButton, DiffView, ExtLink, FixConfBadge, KindBadge, KeyValue, Loading, OriginBadge, PathView,
  PriorityPill, ReachBadge, ScoreBar, SeverityBadge, StateBadge, fmtDate,
} from './ui'

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <section className="mb-6">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-ink-100 mb-2.5"><span className="text-accent">{icon}</span>{title}</h3>
      {children}
    </section>
  )
}

export function FindingTitle({ f, pkg }: { f: Finding; pkg?: PackageInfo | null }) {
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-1.5 mb-1">
        <SeverityBadge s={f.severity} /><KindBadge k={f.kind} /><PriorityPill bucket={f.scores.priority_bucket} value={f.scores.priority} />
        {f.advisory && <span className="mono text-xs text-ink-300">{f.advisory.id}</span>}
      </div>
      <div className="text-base font-semibold text-ink-100 leading-snug truncate">{f.title}</div>
      {pkg && <div className="text-xs text-ink-400 mono mt-0.5">{pkg.name}@{pkg.version ?? '?'} · {pkg.ecosystem} · {pkg.direct ? 'direct' : 'transitive'} · {pkg.scope}</div>}
    </div>
  )
}

export function WhyScore({ f }: { f: Finding }) {
  const groups = ['intrinsic', 'exposure', 'confidence', 'priority']
  const s = f.scores
  return (
    <div className="grid gap-4">
      <div className="grid sm:grid-cols-4 gap-3">
        <div className="card p-3"><ScoreBar label="Intrinsic risk" value={s.intrinsic} color="#fb923c" /></div>
        <div className="card p-3"><ScoreBar label="App exposure" value={s.exposure} color="#f43f5e" /></div>
        <div className="card p-3"><ScoreBar label={`Confidence (${s.confidence_label})`} value={s.confidence} color="#34d399" /></div>
        <div className="card p-3"><ScoreBar label={`Priority (${s.priority_bucket})`} value={s.priority} color="#38bdf8" /></div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-ink-700"><th className="table-head py-2 pr-3">Component</th><th className="table-head pr-3">Factor</th><th className="table-head pr-3">Value</th><th className="table-head pr-3">Effect</th><th className="table-head">Evidence</th></tr></thead>
          <tbody>
            {groups.flatMap((g) => s.factors.filter((x) => x.component === g)).map((x, i) => (
              <tr key={i} className="border-b border-ink-800 align-top">
                <td className="py-2 pr-3 text-ink-400 capitalize">{x.component}</td>
                <td className="pr-3 text-ink-100">{x.factor}</td>
                <td className="pr-3 mono text-xs text-ink-200">{String(x.value ?? '—')}</td>
                <td className="pr-3 mono text-xs text-accent">{x.effect}</td>
                <td className="mono text-[11px] text-ink-400 break-all">{x.evidence ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-ink-400">Formula and weights are documented in <Link to="/settings#scoring" className="link">Settings → Scoring model</Link>. Unknown inputs stay unknown and are never treated as zero risk.</p>
    </div>
  )
}

export function FindingDetail({ findingId }: { findingId: string }) {
  const { scanId } = useScan()
  const { data, loading, error } = useApi<{ finding: Finding; package: PackageInfo | null; plan: Plan | null }>(
    scanId ? `/api/scans/${scanId}/findings/${encodeURIComponent(findingId)}` : null)
  const [showAllPaths, setShowAllPaths] = useState(false)
  if (loading) return <Loading label="Loading finding" />
  if (error || !data) return <Callout tone="bad">{error || 'Finding not found.'}</Callout>
  const { finding: f, package: pkg, plan } = data
  const adv = f.advisory
  const paths = f.paths || []
  return (
    <div className="fade-in">
      <div className="mb-5"><FindingTitle f={f} pkg={pkg} /></div>

      {f.kind !== 'vulnerability' && (
        <Callout tone="warn" title="Heuristic signal — not a confirmed compromise">
          This finding is evidence for review produced by a transparent rule. Confidence: <b>{f.confidence}</b>.
        </Callout>
      )}

      {adv && (
        <Section icon={<ShieldAlert size={16} />} title="Advisory">
          <p className="text-sm text-ink-200 mb-3">{adv.summary}</p>
          <KeyValue items={[
            ['Identifiers', <span className="flex flex-wrap gap-1.5">{adv.aliases.map((a) => (
              <ExtLink key={a} href={a.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${a}` : `https://osv.dev/vulnerability/${a}`}><span className="mono text-xs">{a}</span></ExtLink>))}</span>],
            ['Installed version', <span className="mono">{pkg?.version}</span>],
            ['Affected ranges', <span className="mono text-xs">{adv.affected_ranges.join('  |  ') || '—'}</span>],
            ['Applies to installed?', adv.applies_to_installed === true ? <span className="text-sev-critical flex items-center gap-1"><AlertOctagon size={14} /> Yes — {pkg?.version} is inside the affected range (local check agrees with OSV)</span>
              : adv.applies_to_installed === false ? <span className="text-warn">Disputed — local range evaluation did not confirm OSV's match</span>
                : <span className="text-ink-300 flex items-center gap-1"><CircleHelp size={14} /> Could not be evaluated locally; relying on OSV</span>],
            ['Fixed versions', <span className="mono text-xs">{adv.fixed_versions.join(', ') || 'none published'}</span>],
            ['Severity', <span>{adv.severity} {adv.cvss_score != null && <span className="text-ink-400">· CVSS {adv.cvss_score}</span>} <span className="text-ink-400 text-xs block">{adv.severity_basis}</span></span>],
            ['CVSS vector', adv.cvss_vector ? <span className="mono text-xs">{adv.cvss_vector}</span> : null],
            ['CWE', adv.cwes.join(', ') || null],
            ['Published / modified', `${fmtDate(adv.published)} / ${fmtDate(adv.modified)}`],
            ['Exploitation', <span>{f.exploitation?.summary}{f.exploitation?.epss && <span className="text-ink-400"> · EPSS {(f.exploitation.epss.epss * 100).toFixed(1)}% (percentile {(f.exploitation.epss.percentile * 100).toFixed(0)})</span>}</span>],
            ['Source', <ExtLink href={adv.source_url}>{adv.source_url}</ExtLink>],
          ]} />
          {adv.details && (
            <details className="mt-3 group">
              <summary className="text-xs text-accent cursor-pointer">Advisory details</summary>
              <pre className="mt-2 whitespace-pre-wrap text-xs text-ink-300 bg-ink-950 border border-ink-700 rounded-lg p-3 max-h-72 overflow-auto scrollbar-thin">{adv.details}</pre>
            </details>
          )}
        </Section>
      )}

      {f.kind !== 'vulnerability' && (
        <Section icon={<ShieldAlert size={16} />} title="Observation">
          <p className="text-sm text-ink-100">{f.observation}</p>
          <p className="text-sm text-ink-400 mt-2">{f.explanation}</p>
        </Section>
      )}

      {paths.length > 0 && (
        <Section icon={<Link2 size={16} />} title={`How the application inherits this (${paths.length} path${paths.length > 1 ? 's' : ''})`}>
          {f.blast_radius && (
            <div className="flex flex-wrap gap-2 mb-3 text-xs">
              <span className="chip bg-ink-750 text-ink-200">Components affected: {f.blast_radius.roots}</span>
              <span className="chip bg-ink-750 text-ink-200">Dependents: {f.blast_radius.dependents}</span>
              <span className="chip bg-ink-750 text-ink-200">Depth: {f.blast_radius.depth ?? '?'}</span>
              <span className="chip bg-ink-750 text-ink-200">Via direct deps: {f.blast_radius.direct_dependencies.join(', ') || '—'}</span>
              {!f.blast_radius.path_known && <span className="chip bg-warn/10 text-warn">Path not recorded by manifest format</span>}
            </div>
          )}
          <div className="space-y-2">
            {(showAllPaths ? paths : paths.slice(0, 4)).map((p, i) => <PathView key={i} path={p} labels={labelFor} />)}
          </div>
          {paths.length > 4 && <button className="text-xs link mt-2" onClick={() => setShowAllPaths(!showAllPaths)}>{showAllPaths ? 'Show fewer' : `Show all ${paths.length} paths`}</button>}
        </Section>
      )}

      {f.reachability && (
        <Section icon={<FileCode2 size={16} />} title="Reachability (static evidence)">
          <div className="flex items-center gap-2 mb-2"><ReachBadge level={f.reachability.level} /><span className="text-sm text-ink-100">{f.reachability.label}</span></div>
          <p className="text-sm text-ink-300">{f.reachability.explanation}</p>
          {f.reachability.evidence.filter((e) => e.file).length > 0 && (
            <div className="mt-3 space-y-1.5">
              {f.reachability.evidence.filter((e) => e.file).slice(0, 8).map((e, i) => (
                <div key={i} className="rounded-lg bg-ink-950 border border-ink-700 px-3 py-2">
                  <div className="text-[11px] text-ink-400 mono flex gap-2">
                    <span className={e.kind === 'call' ? 'text-sev-critical' : 'text-ink-300'}>{e.kind === 'call' ? `CALL ${e.symbol}` : 'IMPORT'}</span>
                    <span>{e.file}:{e.line}</span>{e.is_test && <span className="text-warn">test file</span>}
                  </div>
                  <code className="mono text-xs text-ink-100 block mt-0.5 break-all">{e.snippet}</code>
                </div>
              ))}
            </div>
          )}
          {f.reachability.needed && <p className="text-xs text-ink-400 mt-2"><b className="text-ink-300">Evidence still needed for exploitability:</b> {f.reachability.needed}</p>}
          {f.reachability.symbols_considered && f.reachability.symbols_considered.length > 0 && (
            <p className="text-[11px] text-ink-500 mt-1">Symbols considered ({f.reachability.symbol_source}): {f.reachability.symbols_considered.join(', ')}</p>
          )}
        </Section>
      )}

      {f.review && (
        <Section icon={<ShieldCheck size={16} />} title="Independent reviewer">
          {f.review.status === 'confirmed' ? <p className="text-sm text-ok">Confirmed: every claim on this finding is supported by its evidence.</p> : (
            <ul className="text-sm space-y-1">{f.review.corrections.map((c, i) => (
              <li key={i} className="text-warn">Corrected: {String(c.before)} → {String(c.after)} — <span className="text-ink-300">{c.reason}</span></li>))}</ul>
          )}
        </Section>
      )}

      {f.ai_explanation && (
        <Section icon={<Sparkles size={16} />} title="AI explanation">
          <div className="rounded-lg border border-fuchsia-400/30 bg-fuchsia-400/5 p-3">
            <div className="text-[11px] text-fuchsia-200 mb-1.5">{f.ai_explanation.label} · {f.ai_explanation.model}</div>
            <p className="text-sm text-ink-100">{f.ai_explanation.plain_explanation}</p>
            {f.ai_explanation.why_it_matters_here && <p className="text-sm text-ink-300 mt-1.5"><b className="text-ink-200">Why it matters here:</b> {f.ai_explanation.why_it_matters_here}</p>}
            {f.ai_explanation.investigation_steps.length > 0 && (
              <ol className="list-decimal pl-5 text-sm text-ink-200 mt-2 space-y-0.5">{f.ai_explanation.investigation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            )}
          </div>
        </Section>
      )}

      <Section icon={<Scale size={16} />} title="Why this score?">
        <WhyScore f={f} />
      </Section>

      {plan && (
        <Section icon={<Wrench size={16} />} title="Recommended fix">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <StateBadge s={plan.state} /><FixConfBadge c={plan.fix_confidence} />
            {plan.major_change && <span className="chip bg-warn/15 text-warn">breaking-change boundary</span>}
            <span className="text-sm mono text-ink-100">{plan.installed} → {plan.target ?? 'no verified fix'}</span>
          </div>
          {plan.actions.map((a, i) => (
            <div key={i} className="flex items-center justify-between gap-2 rounded-lg bg-ink-950 border border-ink-700 px-3 py-2 mb-1.5">
              <div className="min-w-0"><div className="text-sm text-ink-100">{a.step}</div><code className="mono text-xs text-accent break-all">{a.command}</code></div>
              <CopyButton text={a.command} />
            </div>
          ))}
          {plan.patch && <div className="mt-2"><div className="text-xs text-ink-400 mb-1">Proposed patch (not applied): {plan.patch.file}</div><DiffView diff={plan.patch.diff} /></div>}
          <Link to={`/remediation?pkg=${encodeURIComponent(plan.package_id)}`} className="link text-sm mt-2 inline-block">Open in remediation center →</Link>
        </Section>
      )}

      <Section icon={<CheckCircle2 size={16} />} title="Evidence ledger">
        <ol className="space-y-2">
          {f.evidence.map((e, i) => (
            <li key={i} className="rounded-lg border border-ink-700 bg-ink-850 px-3 py-2">
              <div className="text-sm text-ink-100">{e.observation}</div>
              {e.snippet && <code className="mono text-xs text-ink-300 block mt-1 break-all">{e.snippet}</code>}
              {e.decoded_preview && <div className="text-xs text-warn mt-1">Decoded (static, not executed): <code className="mono">{e.decoded_preview}</code></div>}
              <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] text-ink-400">
                <span>{e.source}</span><OriginBadge o={e.origin} />
                {e.retrieved_at && <span>retrieved {fmtDate(e.retrieved_at)}</span>}
                {e.url && <ExtLink href={e.url}>{e.url}</ExtLink>}
              </div>
            </li>
          ))}
          {adv?.references.slice(0, 12).map((r, i) => (
            <li key={`r${i}`} className="text-xs text-ink-400 flex gap-2"><span className="chip bg-ink-750 text-ink-300">{r.type}</span><ExtLink href={r.url}>{r.url}</ExtLink></li>
          ))}
        </ol>
      </Section>
    </div>
  )
}
