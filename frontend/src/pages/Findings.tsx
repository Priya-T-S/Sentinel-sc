import { ArrowDown, ArrowUp, Download, FileDown, Search } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, qs } from '../api'
import { FindingDetail } from '../components/FindingDetail'
import { PageHeader } from '../components/Layout'
import { useScanGuard } from '../components/NoScan'
import { Card, Drawer, EmptyState, ErrorState, FixConfBadge, KindBadge, PriorityPill, ReachBadge, SeverityBadge, Skeleton, StateBadge } from '../components/ui'
import { useApi, useDebounced } from '../hooks'
import { useRouter } from '../router'
import { labelFor, useScan } from '../state'
import type { Finding } from '../types'

type Sort = 'priority' | 'severity' | 'package' | 'confidence' | 'kind'

export function FindingsPage() {
  const guard = useScanGuard()
  const { scanId, result } = useScan()
  const { search, navigate, path } = useRouter()
  const [q, setQ] = useState(search.get('q') || '')
  const [kind, setKind] = useState(search.get('kind') || '')
  const [severity, setSeverity] = useState(search.get('severity') || '')
  const [eco, setEco] = useState(search.get('ecosystem') || '')
  const [reach, setReach] = useState(search.get('reachability') || '')
  const [rem, setRem] = useState(search.get('remediation') || '')
  const [direct, setDirect] = useState(search.get('direct') || '')
  const [sort, setSort] = useState<Sort>((search.get('sort') as Sort) || 'priority')
  const [order, setOrder] = useState<'asc' | 'desc'>((search.get('order') as 'asc' | 'desc') || 'desc')
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<string | null>(search.get('open'))
  const [exporting, setExporting] = useState(false)
  const dq = useDebounced(q)
  const params = { q: dq, kind, severity, ecosystem: eco, reachability: reach, remediation: rem, direct, sort, order }
  useEffect(() => { setPage(1) }, [dq, kind, severity, eco, reach, rem, direct, sort, order])
  useEffect(() => { navigate(`${path}${qs(params)}`, { replace: true }) }, [dq, kind, severity, eco, reach, rem, direct, sort, order]) // eslint-disable-line react-hooks/exhaustive-deps
  const url = scanId ? `/api/scans/${scanId}/findings${qs({ ...params, page, page_size: 25 })}` : null
  const { data, loading, error, reload } = useApi<{ total: number; items: Finding[]; page: number; page_size: number }>(url)

  if (guard) return <><PageHeader title="Findings explorer" />{guard}</>
  const ecos = Object.keys(result!.stats.by_ecosystem)
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1

  const exportCsv = async () => {
    setExporting(true)
    try {
      const all: Finding[] = []
      for (let p = 1; p < 100; p++) {
        const r = await api.get<{ total: number; items: Finding[] }>(`/api/scans/${scanId}/findings${qs({ ...params, page: p, page_size: 200 })}`)
        all.push(...r.items)
        if (all.length >= r.total) break
      }
      const esc = (v: unknown) => { const s = String(v ?? ''); return /[",\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${s.replace(/^([=+\-@])/, "'$1").replace(/"/g, '""')}"` : s }
      const rows = [['id', 'kind', 'severity', 'priority', 'bucket', 'package', 'version', 'advisory', 'aliases', 'title', 'reachability', 'fixed_versions', 'remediation_state', 'fix_target', 'confidence']]
      for (const f of all) {
        const l = f.package_id ? labelFor(f.package_id) : null
        rows.push([f.id, f.kind, f.severity, String(f.scores.priority ?? ''), f.scores.priority_bucket, l?.name ?? f.file ?? '', l?.version ?? '',
          f.advisory?.id ?? f.signal ?? '', (f.advisory?.aliases || []).join(' '), f.title, f.reachability?.level ?? '', (f.advisory?.fixed_versions || []).join(' '),
          f.remediation?.state ?? '', f.remediation?.target ?? '', f.scores.confidence_label])
      }
      const blob = new Blob([rows.map((r) => r.map(esc).join(',')).join('\n')], { type: 'text/csv' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `sentinel-${scanId}-findings.csv`
      a.click()
      URL.revokeObjectURL(a.href)
    } finally {
      setExporting(false)
    }
  }

  const SortHead = ({ k, label, className = '' }: { k: Sort; label: string; className?: string }) => (
    <th className={`table-head py-2.5 px-3 ${className}`} aria-sort={sort === k ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button className="inline-flex items-center gap-1 hover:text-ink-100" onClick={() => { if (sort === k) setOrder(order === 'asc' ? 'desc' : 'asc'); else { setSort(k); setOrder('desc') } }}>
        {label}{sort === k && (order === 'asc' ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
      </button>
    </th>
  )
  const sel = (value: string, set: (v: string) => void, label: string, opts: [string, string][]) => (
    <label className="grid gap-1"><span className="label">{label}</span>
      <select className="input py-1.5" value={value} onChange={(e) => set(e.target.value)}>
        <option value="">All</option>{opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select></label>
  )
  return (
    <div className="fade-in">
      <PageHeader title="Findings explorer" subtitle="Verified advisory matches and heuristic signals, each with evidence, paths, reachability and a score explanation."
        actions={<>
          <button className="btn-ghost" onClick={exportCsv} disabled={exporting}><FileDown size={15} /> {exporting ? 'Exporting…' : 'CSV (filtered)'}</button>
          <a className="btn-ghost" href={`/api/scans/${scanId}/export/json`}><Download size={15} /> JSON</a>
          <a className="btn-ghost" href={`/api/scans/${scanId}/export/cyclonedx`}><Download size={15} /> SBOM + VEX</a>
        </>} />
      <div className="card px-4 py-3 mb-3 flex flex-wrap items-end gap-3 text-sm">
        <label className="grid gap-1 flex-1 min-w-[14rem]"><span className="label">Search</span>
          <span className="relative"><Search size={15} className="absolute left-2.5 top-2.5 text-ink-400" />
            <input className="input w-full pl-8" placeholder="Package, CVE/GHSA, title, file…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" /></span></label>
        {sel(kind, setKind, 'Type', [['vulnerability', 'Verified vulnerability'], ['suspicious', 'Suspicious'], ['integrity', 'Integrity'], ['maintenance', 'Maintenance'], ['hygiene', 'Hygiene'], ['secret', 'Secret'], ['ci', 'CI/CD']])}
        {sel(severity, setSeverity, 'Severity', [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info'], ['unknown', 'Unknown']])}
        {sel(eco, setEco, 'Ecosystem', ecos.map((e) => [e, e]))}
        {sel(reach, setReach, 'Reachability', [['symbol_call', 'Call-site evidence'], ['imported', 'Imported'], ['transitive_imported', 'Via imported dep'], ['transitive', 'Transitive only'], ['declared_not_imported', 'Not imported'], ['unknown', 'Unknown']])}
        {sel(rem, setRem, 'Remediation', [['safe_candidate', 'Safe candidate'], ['requires_review', 'Requires review'], ['no_verified_fix', 'No verified fix'], ['insufficient_information', 'Insufficient info']])}
        {sel(direct, setDirect, 'Dependency', [['true', 'Direct'], ['false', 'Transitive']])}
      </div>
      {error && <ErrorState message={error} onRetry={reload} />}
      <Card pad={false}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-ink-700"><tr>
              <SortHead k="priority" label="Priority" /><SortHead k="severity" label="Severity" /><SortHead k="kind" label="Type" />
              <th className="table-head px-3">Finding</th><SortHead k="package" label="Package" />
              <th className="table-head px-3">Installed → fix</th><th className="table-head px-3">Reachability</th><SortHead k="confidence" label="Confidence" /><th className="table-head px-3">Remediation</th>
            </tr></thead>
            <tbody>
              {loading && !data && <tr><td colSpan={9} className="p-4"><Skeleton rows={8} /></td></tr>}
              {data?.items.map((f) => {
                const l = f.package_id ? labelFor(f.package_id) : null
                return (
                  <tr key={f.id} className="border-b border-ink-800 hover:bg-ink-800/50 cursor-pointer" onClick={() => setOpen(f.id)}
                    tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setOpen(f.id) }}>
                    <td className="px-3 py-2.5"><PriorityPill bucket={f.scores.priority_bucket} value={f.scores.priority} /></td>
                    <td className="px-3"><SeverityBadge s={f.severity} /></td>
                    <td className="px-3"><KindBadge k={f.kind} /></td>
                    <td className="px-3 max-w-[26rem]"><div className="text-ink-100 truncate">{f.title}</div>
                      <div className="mono text-[11px] text-ink-400 truncate">{f.advisory ? [f.advisory.id, ...f.advisory.cves].join(' · ') : f.signal}{f.paths && f.paths[0] && f.paths[0].length > 2 ? ` · via ${labelFor(f.paths[0][1]).name}` : ''}</div></td>
                    <td className="px-3 mono text-xs text-ink-200 whitespace-nowrap">{l ? l.name : f.file}</td>
                    <td className="px-3 mono text-xs whitespace-nowrap">{l?.version ?? ''}{f.remediation?.target && <span className="text-ok"> → {f.remediation.target}</span>}</td>
                    <td className="px-3">{f.reachability ? <ReachBadge level={f.reachability.level} /> : <span className="text-ink-500">—</span>}</td>
                    <td className="px-3 text-xs text-ink-300 capitalize">{f.scores.confidence_label}</td>
                    <td className="px-3"><div className="flex gap-1"><StateBadge s={f.remediation?.state} />{f.remediation && <FixConfBadge c={f.remediation.fix_confidence} />}</div></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {data && data.total === 0 && <EmptyState title="No findings match" body="Adjust the filters, or this scan has no findings of this type." />}
        </div>
        {data && data.total > 0 && (
          <div className="flex items-center justify-between px-4 py-3 text-xs text-ink-400">
            <span>{data.total} finding(s) · page {data.page} of {pages}</span>
            <div className="flex gap-2">
              <button className="btn-ghost py-1" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
              <button className="btn-ghost py-1" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </div>
        )}
      </Card>
      <Drawer open={!!open} onClose={() => setOpen(null)} title={<span className="text-sm text-ink-300">Finding detail</span>}>
        {open && <FindingDetail findingId={open} />}
      </Drawer>
    </div>
  )
}
