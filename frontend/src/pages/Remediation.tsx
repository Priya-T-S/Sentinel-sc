import { ArrowRight, Beaker, Download, FlaskConical, GitPullRequest, Wrench } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { PageHeader } from '../components/Layout'
import { useScanGuard } from '../components/NoScan'
import { Callout, Card, CopyButton, DiffView, EmptyState, ErrorState, FixConfBadge, Loading, PathView, SEV_STYLE, SeverityBadge, StateBadge } from '../components/ui'
import { useRouter } from '../router'
import { labelFor, useScan } from '../state'
import type { Plan, WhatIfResult } from '../types'

export function RemediationPage() {
  const guard = useScanGuard()
  const { result, scanId } = useScan()
  const { search } = useRouter()
  const focus = search.get('pkg')
  const [whatif, setWhatif] = useState<WhatIfResult | null>(null)
  const [wiLoading, setWiLoading] = useState(false)
  const [wiError, setWiError] = useState<string | null>(null)
  const [stateFilter, setStateFilter] = useState('')
  const focusRef = useRef<HTMLDivElement>(null)
  useEffect(() => { if (focus) setTimeout(() => focusRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200) }, [focus, result])
  if (guard) return <><PageHeader title="Remediation center" />{guard}</>
  const r = result!
  const plans = [...r.remediation.plans]
  const counts = plans.reduce<Record<string, number>>((a, p) => { a[p.state] = (a[p.state] || 0) + 1; return a }, {})
  const shown = plans.filter((p) => !stateFilter || p.state === stateFilter)
  const runWhatIf = async (changes?: Record<string, string>) => {
    setWiLoading(true); setWiError(null)
    try { setWhatif(await api.post<WhatIfResult>(`/api/scans/${scanId}/whatif`, changes ? { changes } : {})) }
    catch (e) { setWiError((e as Error).message) }
    finally { setWiLoading(false) }
  }
  const combined = r.remediation.combined_patch?.files || []
  return (
    <div className="fade-in">
      <PageHeader title="Remediation center"
        subtitle="Fixes are grounded in advisory fixed versions, re-checked against OSV, and checked against declared ranges and parent constraints. Nothing is applied to your repository."
        actions={<>
          {combined.length > 0 && <a className="btn-ghost" href={`/api/scans/${scanId}/export/patch`}><Download size={15} /> Patch (.diff)</a>}
          <a className="btn-ghost" href={`/api/scans/${scanId}/export/html`}><Download size={15} /> Remediation report</a>
          <button className="btn-primary" onClick={() => runWhatIf()} disabled={wiLoading || !plans.length}><FlaskConical size={15} /> {wiLoading ? 'Simulating…' : 'Simulate all fixes'}</button>
        </>} />

      {!plans.length ? <div className="card"><EmptyState icon={<Wrench size={22} />} title="Nothing to remediate" body="No verified vulnerabilities in this scan. Review suspicious signals in the findings explorer." /></div> : (
        <>
          <div className="grid sm:grid-cols-4 gap-3 mb-4">
            {(['safe_candidate', 'requires_review', 'no_verified_fix', 'insufficient_information'] as const).map((s) => (
              <button key={s} onClick={() => setStateFilter(stateFilter === s ? '' : s)} className={`card card-pad text-left transition-colors ${stateFilter === s ? 'ring-1 ring-accent' : 'hover:border-ink-500'}`}>
                <StateBadge s={s} /><div className="text-2xl font-semibold text-ink-100 mt-2 tabular-nums">{counts[s] || 0}</div><div className="text-xs text-ink-400">package plan(s)</div>
              </button>
            ))}
          </div>

          {(whatif || wiError || wiLoading) && (
            <Card title={<span className="flex items-center gap-2"><Beaker size={15} className="text-fuchsia-300" /> What-if comparison</span>} className="mb-4 border-fuchsia-400/30"
              subtitle="SIMULATED — the proposed versions are re-queried against OSV, but the changes have not been applied or rescanned.">
              {wiLoading && <Loading label="Re-querying OSV for proposed versions" />}
              {wiError && <ErrorState message={wiError} />}
              {whatif && !wiLoading && <WhatIfView w={whatif} />}
            </Card>
          )}

          {combined.length > 0 && (
            <Card title={<span className="flex items-center gap-2"><GitPullRequest size={15} /> Combined patch preview</span>} className="mb-4"
              subtitle="One change per manifest, taking the highest version any plan requires. Regenerate the lockfile with your package manager, then rescan to confirm.">
              {combined.map((f) => (
                <div key={f.file} className="mb-3">
                  <div className="flex items-center justify-between mb-1"><span className="mono text-xs text-ink-300">{f.file}</span><CopyButton text={f.diff} label="Copy diff" /></div>
                  <DiffView diff={f.diff} />
                  <p className="text-xs text-ink-400 mt-1">{f.note}</p>
                </div>
              ))}
            </Card>
          )}

          <div className="space-y-3">
            {shown.map((p) => (
              <div key={p.package_id} ref={p.package_id === focus ? focusRef : undefined}>
                <PlanCard p={p} focused={p.package_id === focus} onSimulate={() => p.target && runWhatIf({ [p.package_id]: p.target })} />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function PlanCard({ p, focused, onSimulate }: { p: Plan; focused: boolean; onSimulate: () => void }) {
  const [openPatch, setOpenPatch] = useState(focused)
  return (
    <div className={`card ${focused ? 'ring-1 ring-accent' : ''}`}>
      <div className="px-5 py-4 flex flex-wrap items-center gap-3 border-b border-ink-700/70">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="mono text-base font-semibold text-ink-100">{p.package}</span>
            <span className="mono text-sm text-ink-400">{p.installed}</span><ArrowRight size={14} className="text-ink-500" />
            <span className={`mono text-sm font-semibold ${p.target ? 'text-ok' : 'text-bad'}`}>{p.target ?? 'no verified fix'}</span>
          </div>
          <div className="text-xs text-ink-400 mt-0.5">{p.ecosystem} · {p.direct ? 'direct' : 'transitive'} · {p.scope} · fixes {p.advisories.length} advisor{p.advisories.length > 1 ? 'ies' : 'y'}: <span className="mono">{p.advisories.slice(0, 4).join(', ')}{p.advisories.length > 4 ? '…' : ''}</span></div>
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          <StateBadge s={p.state} /><FixConfBadge c={p.fix_confidence} />
          {p.major_change && <span className="chip bg-warn/15 text-warn" title="Crosses a semver breaking-change boundary">major/0.x change</span>}
          {p.target && <button className="btn-ghost py-1 text-xs" onClick={onSimulate}><FlaskConical size={13} /> Simulate</button>}
        </div>
      </div>
      <div className="px-5 py-4 grid lg:grid-cols-2 gap-5">
        <div>
          <div className="label mb-2">Steps</div>
          {p.actions.length === 0 && <p className="text-sm text-ink-400">{p.reason || 'No automated action available.'}</p>}
          {p.actions.map((a, i) => (
            <div key={i} className="rounded-lg bg-ink-950 border border-ink-700 px-3 py-2 mb-2">
              <div className="flex items-center justify-between gap-2"><span className="text-sm text-ink-100">{i + 1}. {a.step}</span><CopyButton text={a.command} /></div>
              <code className="mono text-xs text-accent block break-all">{a.command}</code>
              <div className="text-xs text-ink-400 mt-0.5">{a.why}</div>
            </div>
          ))}
          {p.alternatives.map((a, i) => <div key={i} className="text-xs text-ink-300 mt-1"><span className="chip bg-ink-750 text-ink-200 mr-1">{a.action}</span>{a.detail}</div>)}
          {p.evidence && (
            <div className="mt-3"><div className="label mb-1">Fix evidence</div>
              <ul className="text-xs text-ink-300 space-y-1 list-disc pl-4">{p.evidence.map((e, i) => <li key={i}>{e.observation} <span className="text-ink-500">({e.source})</span></li>)}</ul></div>
          )}
          {p.candidates_checked && p.candidates_checked.length > 0 && (
            <details className="mt-2"><summary className="text-xs link cursor-pointer">Candidate versions checked against OSV ({p.candidates_checked.length})</summary>
              <ul className="text-xs mono mt-1 space-y-0.5">{p.candidates_checked.map((c) => (
                <li key={c.version} className={c.known_advisories === null ? 'text-warn' : c.known_advisories.length ? 'text-bad' : 'text-ok'}>
                  {c.version}: {c.known_advisories === null ? 'not verified' : c.known_advisories.length ? c.known_advisories.join(', ') : 'no known advisories'}</li>))}</ul>
            </details>
          )}
        </div>
        <div>
          <div className="label mb-2">Compatibility checks</div>
          <ul className="space-y-1.5">
            {p.compatibility.map((c, i) => (
              <li key={i} className="text-sm">
                <span className={`chip mr-1.5 ${c.result === 'pass' || c.result.startsWith('resolves') || c.result === 'via parent' ? 'bg-ok/10 text-ok' : c.result === 'unknown' ? 'bg-ink-700 text-ink-300' : 'bg-warn/10 text-warn'}`}>{c.result}</span>
                <span className="text-ink-200">{c.check}</span><div className="text-xs text-ink-400 mt-0.5">{c.detail}</div>
              </li>
            ))}
          </ul>
          {p.paths.length > 0 && (
            <div className="mt-3"><div className="label mb-1.5">Paths to address ({p.paths.length})</div>
              <div className="space-y-1.5">{p.paths.slice(0, 4).map((path, i) => <PathView key={i} path={path} labels={labelFor} />)}</div></div>
          )}
        </div>
      </div>
      {p.patch && (
        <div className="px-5 pb-4">
          <button className="text-xs link" onClick={() => setOpenPatch(!openPatch)}>{openPatch ? 'Hide' : 'Show'} patch for this package ({p.patch.file})</button>
          {openPatch && <div className="mt-2"><DiffView diff={p.patch.diff} /><p className="text-xs text-ink-400 mt-1">{p.patch.note}</p></div>}
        </div>
      )}
    </div>
  )
}

function WhatIfView({ w }: { w: WhatIfResult }) {
  const sevs = ['critical', 'high', 'medium', 'low'] as const
  const max = Math.max(1, ...sevs.map((s) => w.before.severity[s]))
  return (
    <div>
      <Callout tone="warn" title={w.label}>{w.limitations.join(' ')}</Callout>
      <div className="grid md:grid-cols-3 gap-4 mt-4">
        {[['Verified vulnerabilities', w.before.vulnerabilities, w.after.vulnerabilities], ['P1 findings', w.before.p1, w.after.p1], ['Max priority', Math.round(w.before.max_priority), Math.round(w.after.max_priority)]].map(([l, b, a]) => (
          <div key={l as string} className="card p-4">
            <div className="label">{l}</div>
            <div className="flex items-baseline gap-3 mt-1"><span className="text-2xl font-semibold text-ink-300 tabular-nums line-through decoration-ink-500">{b}</span><ArrowRight size={16} className="text-ink-500" /><span className="text-3xl font-semibold text-ok tabular-nums">{a}</span></div>
          </div>
        ))}
      </div>
      <div className="mt-4 grid md:grid-cols-2 gap-6">
        <div>
          <div className="label mb-2">By severity (before → after)</div>
          {sevs.map((s) => (
            <div key={s} className="grid grid-cols-[5rem_1fr_4rem] items-center gap-2 text-xs mb-1.5">
              <SeverityBadge s={s} />
              <div className="space-y-[2px]">
                <div className="h-2 rounded-r bg-ink-600" style={{ width: `${(100 * w.before.severity[s]) / max}%` }} title={`before: ${w.before.severity[s]}`} />
                <div className="h-2 rounded-r" style={{ width: `${(100 * w.after.severity[s]) / max}%`, background: SEV_STYLE[s].hex }} title={`after: ${w.after.severity[s]}`} />
              </div>
              <span className="tabular-nums text-ink-200 text-right">{w.before.severity[s]} → {w.after.severity[s]}</span>
            </div>
          ))}
          <div className="text-[11px] text-ink-400 mt-1">Grey = current · colour = simulated</div>
        </div>
        <div>
          <div className="label mb-2">Proposed version changes</div>
          <table className="w-full text-xs"><tbody>{w.changes.map((c) => (
            <tr key={c.package_id} className="border-b border-ink-800">
              <td className="py-1 mono text-ink-100">{c.name}</td><td className="mono text-ink-400">{c.from} → <span className="text-ok">{c.to}</span></td>
              <td className="tabular-nums text-right">{c.before} → {c.after ?? '?'}</td>
              <td className="text-right"><span className={`chip ${c.status === 'verified' ? 'bg-ok/10 text-ok' : 'bg-warn/10 text-warn'}`}>{c.status === 'verified' ? 'OSV-checked' : c.status}</span></td>
            </tr>))}</tbody></table>
          {w.remaining.length > 0 && <div className="text-xs text-warn mt-2">Remaining after simulation: {w.remaining.map((x) => x.advisory).join(', ')}</div>}
        </div>
      </div>
    </div>
  )
}
