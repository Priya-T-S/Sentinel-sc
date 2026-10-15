import { AlertTriangle, BadgeCheck, CheckCircle2, CircleHelp, Search, ShieldX, XCircle } from 'lucide-react'
import { useState } from 'react'
import { FindingDetail } from '../components/FindingDetail'
import { PageHeader } from '../components/Layout'
import { useScanGuard } from '../components/NoScan'
import { Callout, Card, Drawer, EmptyState, ErrorState, ExtLink, FixConfBadge, KeyValue, KindBadge, Loading, OriginBadge, PathView, PriorityPill, ReachBadge, SeverityBadge, StateBadge, fmtDate } from '../components/ui'
import { useApi, useDebounced } from '../hooks'
import { Link, useRouter } from '../router'
import { labelFor, useScan } from '../state'
import type { Finding, PackageInfo, Plan } from '../types'

interface PkgRow { id: string; name: string; version: string | null; ecosystem: string; direct: boolean; vuln_status: string; vulnerability_count: number; signal_count: number; max_severity: string | null; risk: { priority: number | null; priority_bucket: string } }

export function PackagePage() {
  const guard = useScanGuard()
  const { scanId } = useScan()
  const { search, navigate } = useRouter()
  const id = search.get('id')
  const [q, setQ] = useState('')
  const [risky, setRisky] = useState(true)
  const dq = useDebounced(q)
  const list = useApi<{ total: number; items: PkgRow[] }>(scanId ? `/api/scans/${scanId}/packages?page_size=500&only_risky=${risky && !dq}&q=${encodeURIComponent(dq)}` : null)
  if (guard) return <><PageHeader title="Package intelligence" />{guard}</>
  return (
    <div className="fade-in">
      <PageHeader title="Package intelligence" subtitle="Metadata, trust signals, provenance and known vulnerabilities for each dependency — with explicit uncertainty." />
      <div className="grid lg:grid-cols-[300px_1fr] gap-4">
        <div className="card p-3 h-fit lg:sticky lg:top-20">
          <span className="relative block"><Search size={15} className="absolute left-2.5 top-2.5 text-ink-400" />
            <input className="input w-full pl-8" placeholder="Search packages…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search packages" /></span>
          <label className="flex items-center gap-2 text-xs text-ink-300 mt-2 px-1"><input type="checkbox" className="accent-sky-400" checked={risky} onChange={(e) => setRisky(e.target.checked)} /> Only packages with findings</label>
          <div className="mt-2 max-h-[70vh] overflow-y-auto scrollbar-thin -mx-1">
            {list.loading && <Loading />}
            {list.data?.items.map((p) => (
              <button key={p.id} onClick={() => navigate(`/package?id=${encodeURIComponent(p.id)}`)}
                className={`w-full text-left px-2.5 py-2 rounded-lg flex items-center gap-2 text-sm ${id === p.id ? 'bg-accent/10 ring-1 ring-accent/30' : 'hover:bg-ink-800'}`}>
                <span className="flex-1 min-w-0"><span className="block truncate text-ink-100 mono text-xs">{p.name}</span><span className="block text-[11px] text-ink-400">{p.version ?? '?'} · {p.ecosystem}{p.direct ? ' · direct' : ''}</span></span>
                {p.vulnerability_count > 0 && <SeverityBadge s={p.max_severity} />}
                {p.vuln_status === 'unverified' && <span className="chip bg-warn/10 text-warn">?</span>}
              </button>
            ))}
            {list.data && !list.data.items.length && <div className="text-xs text-ink-400 p-3">No packages.</div>}
          </div>
        </div>
        <div>{id ? <PackageDetail id={id} /> : <div className="card"><EmptyState title="Select a package" body="Choose a dependency on the left to inspect its trust profile and evidence." /></div>}</div>
      </div>
    </div>
  )
}

const TRUST_ICON: Record<string, JSX.Element> = {
  good: <CheckCircle2 size={15} className="text-ok" />, verified: <BadgeCheck size={15} className="text-ok" />, present: <CheckCircle2 size={15} className="text-accent" />, info: <CircleHelp size={15} className="text-ink-400" />,
  warn: <AlertTriangle size={15} className="text-warn" />, absent: <AlertTriangle size={15} className="text-ink-400" />, missing: <XCircle size={15} className="text-bad" />,
  bad: <XCircle size={15} className="text-bad" />, unknown: <CircleHelp size={15} className="text-ink-500" />,
}

function PackageDetail({ id }: { id: string }) {
  const { scanId } = useScan()
  const [open, setOpen] = useState<string | null>(null)
  const { data, loading, error, reload } = useApi<{ package: PackageInfo; findings: Finding[]; plan: Plan | null; paths: string[][]; dependencies: { id: string; name: string; version: string }[]; dependents: { id: string; name: string; version: string }[] }>(
    scanId ? `/api/scans/${scanId}/package?id=${encodeURIComponent(id)}` : null)
  if (loading) return <Loading />
  if (error || !data) return <ErrorState message={error || 'Not found'} onRetry={reload} />
  const p = data.package
  const reg = p.registry
  const unknowns: string[] = []
  if (p.vuln_status !== 'checked') unknowns.push(p.vuln_status_reason || 'Vulnerability status not verified.')
  if (!reg?.available) unknowns.push('Registry metadata was not retrieved (ecosystem not supported for metadata, lookup cap reached, or provider unavailable). Maintenance and provenance signals are unknown — not assumed good or bad.')
  if (p.trust.items.find((t) => t.key === 'provenance' && t.status !== 'verified')) unknowns.push('No verified build provenance: the published artifact cannot be tied to a specific source commit and build.')
  if (!p.imported_in.length && p.direct) unknowns.push('No import found in scanned source; usage may be dynamic or via tooling.')
  if (!data.paths.length) unknowns.push('No dependency path was established from an application manifest.')
  return (
    <div className="space-y-4 fade-in">
      <div className="card card-pad">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex gap-1.5 flex-wrap mb-1.5">
              {p.max_severity && <SeverityBadge s={p.max_severity} />}<span className="chip bg-ink-750 text-ink-200">{p.ecosystem}</span>
              <span className="chip bg-ink-750 text-ink-200">{p.direct ? 'direct' : 'transitive'}</span><span className="chip bg-ink-750 text-ink-200">{p.scope}</span>
              <span className="chip bg-ink-750 text-ink-200">{p.source_type}</span><PriorityPill bucket={p.risk.priority_bucket === 'none' ? undefined : p.risk.priority_bucket} value={p.risk.priority} />
            </div>
            <h2 className="text-2xl font-semibold text-ink-100 mono break-all">{p.name}<span className="text-ink-400">@{p.version ?? '?'}</span></h2>
            {reg?.description && <p className="text-sm text-ink-300 mt-1">{reg.description}</p>}
          </div>
          <div className="text-right text-sm">
            <div className="label">Vulnerability status</div>
            <div className={p.vuln_status === 'checked' ? 'text-ok' : p.vuln_status === 'unverified' ? 'text-warn font-semibold' : 'text-ink-300'}>
              {p.vuln_status === 'checked' ? `Checked · ${p.vulnerability_count} known` : p.vuln_status === 'unverified' ? 'NOT VERIFIED' : 'Not applicable'}
            </div>
            {p.osv_checked_at && <div className="text-xs text-ink-400 flex items-center gap-1 justify-end">{fmtDate(p.osv_checked_at)} <OriginBadge o={p.osv_origin} /></div>}
          </div>
        </div>
        <div className="mt-4"><KeyValue items={[
          ['Package URL', p.purl && <span className="mono text-xs">{p.purl}</span>],
          ['Declared as', p.declared_spec && <span className="mono text-xs">{p.declared_spec}</span>],
          ['Source file', <span className="mono text-xs">{p.source_file}</span>],
          ['Resolved from', p.resolved && <span className="mono text-xs break-all">{p.resolved}</span>],
          ['Integrity', p.integrity && <span className="mono text-xs break-all">{p.integrity.slice(0, 80)}{p.integrity.length > 80 ? '…' : ''}</span>],
          ['Imported in', p.imported_in.length ? p.imported_in.map((i) => `${i.file}:${i.line}${i.is_test ? ' (test)' : ''}`).join(', ') : 'no imports found'],
        ]} /></div>
      </div>

      <div className="grid xl:grid-cols-2 gap-4">
        <Card title="Supply-chain trust profile" subtitle="Each signal shows its source. 'Verified' = checked cryptographically (Sigstore); 'present' = the metadata exists but was not verified.">
          <ul className="space-y-2.5">
            {p.trust.items.map((t) => (
              <li key={t.key} className="flex gap-2.5">
                <span className="mt-0.5">{TRUST_ICON[t.status] || TRUST_ICON.unknown}</span>
                <div className="min-w-0"><div className="text-sm text-ink-100">{t.label} <span className="text-xs text-ink-400">· {t.status}</span></div>
                  <div className="text-xs text-ink-300 break-words">{t.detail}</div><div className="text-[11px] text-ink-500">{t.source}</div></div>
              </li>
            ))}
          </ul>
          {p.trust.scorecard && (
            <details className="mt-3"><summary className="text-xs link cursor-pointer">OpenSSF Scorecard checks ({p.trust.scorecard.checks.length})</summary>
              <table className="w-full text-xs mt-2"><tbody>{p.trust.scorecard.checks.map((c) => (
                <tr key={c.name} className="border-b border-ink-800"><td className="py-1 text-ink-200">{c.name}</td><td className="tabular-nums text-right pr-2">{c.score < 0 ? 'n/a' : c.score}</td><td className="text-ink-400">{c.reason}</td></tr>))}</tbody></table>
            </details>
          )}
        </Card>
        <Card title="Registry metadata & history" subtitle={reg?.available ? <span className="flex items-center gap-1">Retrieved {fmtDate(reg.retrieved_at)} <OriginBadge o={reg.origin} /></span> : 'Not available'}>
          {reg?.available ? (
            <>
              <KeyValue items={[
                ['First published', fmtDate(reg.created)], ['This version published', fmtDate(reg.published)], ['Latest version', <span className="mono">{reg.latest}</span>],
                ['Versions', reg.version_count], ['License', reg.license], ['Repository', <ExtLink href={reg.repository}>{reg.repository}</ExtLink>],
                ['Maintainers', reg.maintainers?.join(', ')], ['Deprecated', reg.deprecated ? <span className="text-warn">{reg.deprecated}</span> : 'no'],
              ]} />
              {reg.recent_versions && reg.recent_versions.length > 0 && (
                <div className="mt-3"><div className="label mb-1">Recent releases</div>
                  <div className="flex flex-wrap gap-1">{reg.recent_versions.map((v) => (
                    <span key={v.version} title={fmtDate(v.published)} className={`chip mono ${v.version === p.version ? 'bg-accent/15 text-accent' : 'bg-ink-750 text-ink-300'}`}>{v.version}</span>))}</div></div>
              )}
            </>
          ) : <p className="text-sm text-ink-400">Registry metadata is fetched for npm and PyPI packages (bounded per scan). Missing metadata is reported as unknown — never as a risk on its own.</p>}
        </Card>
      </div>

      {p.provenance && p.provenance.status !== 'absent' && <ProvenanceCard pv={p.provenance} name={p.name} version={p.version} />}

      <Card title="Explicit uncertainty" subtitle="What SENTINEL-SC could not establish for this package">
        {unknowns.length ? <ul className="list-disc pl-5 text-sm text-ink-300 space-y-1">{unknowns.map((u, i) => <li key={i}>{u}</li>)}</ul> : <p className="text-sm text-ink-400">No major gaps for this package.</p>}
      </Card>

      <Card title={`Findings (${data.findings.length})`} pad={false}>
        {data.findings.length === 0 ? <div className="p-5 text-sm text-ink-400">{p.vuln_status === 'checked' ? 'No known vulnerabilities or signals for this exact version.' : 'No findings — but vulnerability status is not verified.'}</div> : (
          <ul className="divide-y divide-ink-800">{data.findings.map((f) => (
            <li key={f.id}><button className="w-full text-left px-5 py-3 hover:bg-ink-800/60 flex items-center gap-3" onClick={() => setOpen(f.id)}>
              <PriorityPill bucket={f.scores.priority_bucket} value={f.scores.priority} /><SeverityBadge s={f.severity} /><KindBadge k={f.kind} />
              <span className="flex-1 text-sm text-ink-100 truncate">{f.title}</span>
              {f.reachability && <ReachBadge level={f.reachability.level} />}
            </button></li>))}</ul>
        )}
      </Card>

      <div className="grid xl:grid-cols-2 gap-4">
        <Card title={`Dependency paths (${data.paths.length})`}>
          {data.paths.length ? <div className="space-y-2">{data.paths.slice(0, 12).map((path, i) => <PathView key={i} path={path} labels={labelFor} />)}</div> : <p className="text-sm text-ink-400">No path recorded.</p>}
          <Link className="link text-xs mt-3 inline-block" to={`/graph?node=${encodeURIComponent(p.id)}`}>Show on attack graph →</Link>
        </Card>
        <Card title="Neighbours">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><div className="label mb-1">Required by ({data.dependents.length})</div>{data.dependents.slice(0, 20).map((d) => d.id.startsWith('root:') ? <div key={d.id} className="text-accent text-xs">{labelFor(d.id).name}</div> : <Link key={d.id} className="block link mono text-xs" to={`/package?id=${encodeURIComponent(d.id)}`}>{d.name}@{d.version}</Link>)}</div>
            <div><div className="label mb-1">Depends on ({data.dependencies.length})</div>{data.dependencies.slice(0, 20).map((d) => <Link key={d.id} className="block link mono text-xs" to={`/package?id=${encodeURIComponent(d.id)}`}>{d.name}@{d.version}</Link>)}</div>
          </div>
        </Card>
      </div>

      {data.plan && (
        <Card title="Remediation" actions={<Link className="btn-ghost" to={`/remediation?pkg=${encodeURIComponent(p.id)}`}>Open plan</Link>}>
          <div className="flex items-center gap-2 flex-wrap"><StateBadge s={data.plan.state} /><FixConfBadge c={data.plan.fix_confidence} /><span className="mono text-sm text-ink-100">{data.plan.installed} → {data.plan.target ?? 'no verified fix'}</span></div>
          {data.plan.reason && <div className="mt-2"><Callout tone="warn">{data.plan.reason}</Callout></div>}
        </Card>
      )}
      <Drawer open={!!open} onClose={() => setOpen(null)} title={<span className="text-sm text-ink-300">Finding detail</span>}>{open && <FindingDetail findingId={open} />}</Drawer>
    </div>
  )
}

function ProvenanceCard({ pv, name, version }: { pv: NonNullable<PackageInfo['provenance']>; name: string; version: string | null }) {
  const ok = pv.status === 'verified'
  const bad = pv.status === 'invalid' || pv.status === 'repo_mismatch'
  const commitUrl = pv.repository && pv.commit ? `${pv.repository}/commit/${pv.commit}` : undefined
  return (
    <Card title={<span className="flex items-center gap-2">{ok ? <BadgeCheck size={16} className="text-ok" /> : bad ? <ShieldX size={16} className="text-bad" /> : <CircleHelp size={16} className="text-ink-400" />}
      Build provenance — {ok ? 'cryptographically verified' : bad ? 'FAILED verification' : 'not verified'}</span>}
      subtitle="SLSA provenance published to npm, checked with Sigstore: signature, signing identity (GitHub Actions), public transparency log, and the artifact's SHA-512.">
      {(ok || bad) && pv.repository ? (
        <KeyValue items={[
          ['Package', <span className="mono">{name}@{version}</span>],
          ['Built from', <ExtLink href={pv.repository}>{pv.repository}</ExtLink>],
          ['Commit', <ExtLink href={commitUrl}><span className="mono">{pv.commit}</span></ExtLink>],
          ['Workflow', <span className="mono text-xs">{pv.workflow} ({pv.ref})</span>],
          ['Build run', pv.run_url ? <ExtLink href={pv.run_url}>{pv.run_url}</ExtLink> : null],
          ['Builder', <span className="mono text-xs">{pv.builder}</span>],
          ['Transparency log', pv.rekor_url ? <ExtLink href={pv.rekor_url}>Rekor entry #{pv.rekor_log_index}</ExtLink> : null],
          ['Signed at', fmtDate(pv.signed_at)],
          ['Artifact hash checked against', pv.digest_source === 'lockfile' ? 'your lockfile' : 'registry metadata'],
          ['Declared repository', pv.declared_repository ?? 'matches'],
        ]} />
      ) : null}
      <div className="mt-3"><Callout tone={ok ? 'ok' : bad ? 'bad' : 'warn'}>{pv.reason}</Callout></div>
    </Card>
  )
}
