import { GitCompare, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api'
import { PageHeader } from '../components/Layout'
import { Card, EmptyState, ErrorState, Loading, SeverityBadge, ago, fmtDate } from '../components/ui'
import { useApi } from '../hooks'
import { useRouter } from '../router'
import { useScan } from '../state'

interface Brief { fingerprint: string; kind: string; title: string; severity: string; package: string; version: string | null; advisory: string | null; priority: number | null }
interface Compare {
  base: { id: string; finished_at: string }; head: { id: string; finished_at: string }
  new_findings: Brief[]; removed_findings: Brief[]; changed_findings: (Brief & { changes: Record<string, [unknown, unknown]> })[]
  packages_added: { ecosystem: string; name: string; version: string }[]; packages_removed: { ecosystem: string; name: string; version: string }[]
  packages_changed: { ecosystem: string; name: string; from: string; to: string }[]
}

export function HistoryPage() {
  const { scans, refreshScans, setScanId, scanId } = useScan()
  const { navigate } = useRouter()
  const [picked, setPicked] = useState<string[]>([])
  const [err, setErr] = useState<string | null>(null)
  const done = scans.filter((s) => s.status === 'completed')
  const [base, head] = picked.length === 2 ? [...picked].sort((a, b) => (scans.find((s) => s.id === a)!.created_at - scans.find((s) => s.id === b)!.created_at)) : [null, null]
  const cmp = useApi<Compare>(base && head ? `/api/compare/${base}/${head}` : null)
  const toggle = (id: string) => setPicked((p) => p.includes(id) ? p.filter((x) => x !== id) : [...p.slice(-1), id])
  const del = async (id: string) => {
    if (!window.confirm('Delete this scan and its stored results?')) return
    try { await api.del(`/api/scans/${id}`); setPicked((p) => p.filter((x) => x !== id)); if (id === scanId) setScanId(null); await refreshScans() }
    catch (e) { setErr((e as Error).message) }
  }
  return (
    <div className="fade-in">
      <PageHeader title="History & risk regression" subtitle="Select two completed scans to see newly introduced, removed and changed findings and dependency versions." />
      {err && <div className="mb-3"><ErrorState message={err} /></div>}
      <Card pad={false} className="mb-4">
        {!scans.length ? <EmptyState title="No scans yet" body="Scans you run appear here. Retention is configurable in Settings." /> : (
          <div className="overflow-x-auto"><table className="w-full text-sm">
            <thead className="border-b border-ink-700"><tr>
              <th className="table-head px-4 py-2.5 w-10"><span className="sr-only">Compare</span></th><th className="table-head px-3">Source</th><th className="table-head px-3">When</th><th className="table-head px-3">Status</th>
              <th className="table-head px-3 text-right">Packages</th><th className="table-head px-3 text-right">Vulns (C/H/M/L)</th><th className="table-head px-3 text-right">Signals</th><th className="table-head px-3">Gate</th><th className="table-head px-3" />
            </tr></thead>
            <tbody>{scans.map((s) => (
              <tr key={s.id} className={`border-b border-ink-800 ${s.id === scanId ? 'bg-accent/5' : ''}`}>
                <td className="px-4 py-2"><input type="checkbox" className="accent-sky-400" disabled={s.status !== 'completed'} checked={picked.includes(s.id)} onChange={() => toggle(s.id)} aria-label={`Select scan ${s.id} for comparison`} /></td>
                <td className="px-3"><button className="link text-left" disabled={s.status !== 'completed'} onClick={() => { setScanId(s.id); navigate('/') }}>{s.source_name}</button>
                  <div className="text-[11px] text-ink-500 mono">{s.id}{s.is_demo ? ' · demo' : ''}{s.summary?.offline ? ' · offline' : ''}</div></td>
                <td className="px-3 text-xs text-ink-300" title={fmtDate(s.created_at)}>{ago(s.created_at)}</td>
                <td className="px-3"><span className={`chip ${s.status === 'completed' ? (s.summary?.status === 'complete' ? 'bg-ok/10 text-ok' : 'bg-warn/10 text-warn') : s.status === 'failed' ? 'bg-bad/10 text-bad' : 'bg-ink-700 text-ink-300'}`}>{s.status === 'completed' ? s.summary?.status : s.status}</span>
                  {s.error && <div className="text-[11px] text-bad max-w-[16rem] truncate" title={s.error}>{s.error}</div>}</td>
                <td className="px-3 text-right tabular-nums">{s.summary?.packages ?? '—'}</td>
                <td className="px-3 text-right tabular-nums">{s.summary ? `${s.summary.vulnerabilities} (${s.summary.severity.critical}/${s.summary.severity.high}/${s.summary.severity.medium}/${s.summary.severity.low})` : '—'}</td>
                <td className="px-3 text-right tabular-nums">{s.summary?.suspicious_signals ?? '—'}</td>
                <td className="px-3"><span className={`chip uppercase ${s.summary?.policy === 'fail' ? 'bg-bad/10 text-bad' : s.summary?.policy === 'warn' ? 'bg-warn/10 text-warn' : s.summary?.policy === 'pass' ? 'bg-ok/10 text-ok' : 'bg-ink-700 text-ink-400'}`}>{s.summary?.policy ?? '—'}</span></td>
                <td className="px-3 text-right"><button className="p-1.5 rounded hover:bg-ink-750 text-ink-400 hover:text-bad" onClick={() => del(s.id)} aria-label={`Delete scan ${s.id}`}><Trash2 size={14} /></button></td>
              </tr>))}</tbody>
          </table></div>
        )}
      </Card>

      {picked.length < 2 ? (
        <div className="card"><EmptyState icon={<GitCompare size={22} />} title="Compare two scans" body={done.length < 2 ? 'Run at least two scans (e.g. before and after applying a fix).' : 'Tick two scans above.'} /></div>
      ) : cmp.loading ? <Loading label="Comparing" /> : cmp.error ? <ErrorState message={cmp.error} /> : cmp.data && (
        <div className="grid lg:grid-cols-2 gap-4 fade-in">
          <Card title={`Newly introduced (${cmp.data.new_findings.length})`} subtitle={`in ${cmp.data.head.id} vs ${cmp.data.base.id}`}><BriefList items={cmp.data.new_findings} tone="bad" /></Card>
          <Card title={`Resolved / removed (${cmp.data.removed_findings.length})`}><BriefList items={cmp.data.removed_findings} tone="ok" /></Card>
          <Card title={`Changed findings (${cmp.data.changed_findings.length})`} subtitle="Version, severity, priority or evidence changed">
            <ul className="space-y-1.5 text-sm max-h-80 overflow-y-auto scrollbar-thin">{cmp.data.changed_findings.map((c) => (
              <li key={c.fingerprint}><span className="text-ink-100">{c.title}</span> <span className="text-xs text-ink-400">{Object.entries(c.changes).map(([k, [a, b]]) => k === 'evidence' ? 'evidence changed' : `${k}: ${a} → ${b}`).join('; ')}</span></li>))}
              {!cmp.data.changed_findings.length && <li className="text-ink-400">None</li>}</ul>
          </Card>
          <Card title="Dependency changes">
            <div className="text-xs space-y-2 max-h-80 overflow-y-auto scrollbar-thin">
              {cmp.data.packages_changed.map((p) => <div key={p.ecosystem + p.name} className="mono"><span className="text-ink-100">{p.name}</span> <span className="text-ink-400">{p.from} → </span><span className="text-accent">{p.to}</span></div>)}
              {cmp.data.packages_added.map((p) => <div key={'a' + p.name} className="mono text-warn">+ {p.name}@{p.version} <span className="text-ink-500">(new dependency)</span></div>)}
              {cmp.data.packages_removed.map((p) => <div key={'r' + p.name} className="mono text-ink-400">− {p.name}@{p.version}</div>)}
              {!cmp.data.packages_changed.length && !cmp.data.packages_added.length && !cmp.data.packages_removed.length && <div className="text-ink-400">No dependency changes.</div>}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

function BriefList({ items, tone }: { items: Brief[]; tone: 'ok' | 'bad' }) {
  if (!items.length) return <p className="text-sm text-ink-400">None.</p>
  return (
    <ul className="space-y-1.5 max-h-80 overflow-y-auto scrollbar-thin">{items.map((b) => (
      <li key={b.fingerprint} className="flex items-center gap-2 text-sm"><SeverityBadge s={b.severity} />
        <span className={`flex-1 truncate ${tone === 'ok' ? 'text-ink-300' : 'text-ink-100'}`}>{b.title}</span>
        <span className="mono text-[11px] text-ink-400">{b.package}{b.version ? `@${b.version}` : ''}</span></li>))}</ul>
  )
}
