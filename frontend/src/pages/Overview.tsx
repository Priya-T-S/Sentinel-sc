import { AlertTriangle, Bug, CheckCircle2, Database, Download, Eye, Layers, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react'
import { useState } from 'react'
import { FindingDetail } from '../components/FindingDetail'
import { HBars, SeverityBar, TrendLine } from '../components/charts'
import { PageHeader } from '../components/Layout'
import { useScanGuard } from '../components/NoScan'
import { Callout, Card, Drawer, KindBadge, OriginBadge, PriorityPill, REACH_META, SeverityBadge, Stat, StateBadge, ago, fmtDate } from '../components/ui'
import { Link, useRouter } from '../router'
import { labelFor, useScan } from '../state'

export function OverviewPage() {
  const guard = useScanGuard()
  const { result, scans, scanId } = useScan()
  const { navigate } = useRouter()
  const [open, setOpen] = useState<string | null>(null)
  if (guard) return <><PageHeader title="Security posture" />{guard}</>
  const r = result!
  const s = r.summary
  const pol = r.policy
  const trend = scans.filter((x) => x.status === 'completed' && x.summary && x.source_name === r.scan.source_name)
    .map((x) => ({ t: x.created_at, v: x.summary!.vulnerabilities, note: `max priority ${Math.round(x.summary!.max_priority ?? 0)}` })).reverse()
  const verdictTone = pol.verdict === 'fail' ? 'text-bad' : pol.verdict === 'warn' ? 'text-warn' : 'text-ok'
  const VerdictIcon = pol.verdict === 'fail' ? XCircle : pol.verdict === 'warn' ? AlertTriangle : CheckCircle2
  const reachRows = Object.entries(s.reachability).sort((a, b) => (REACH_META[b[0]]?.rank ?? 0) - (REACH_META[a[0]]?.rank ?? 0))
  return (
    <div className="fade-in">
      <PageHeader
        title="Security posture"
        subtitle={<>{r.scan.source_name} · scanned {fmtDate(r.scan.finished_at)} in {r.scan.duration_seconds}s · engine {r.scan.engine_version}</>}
        actions={<>
          <a className="btn-ghost" href={`/api/scans/${scanId}/export/html`}><Download size={15} /> HTML report</a>
          <a className="btn-ghost" href={`/api/scans/${scanId}/export/json`}><Download size={15} /> JSON</a>
          <Link className="btn-primary" to="/findings">Explore findings</Link>
        </>}
      />

      {r.scan.status !== 'complete' && (
        <div className="mb-5">
          <Callout tone="warn" title="Partial result — some data could not be verified">
            {s.unverified_packages > 0 && <>{s.unverified_packages} package(s) could not be checked against vulnerability data (shown as <b>Not verified</b>, never as clean). </>}
            {r.coverage.outcomes.some((o) => o.status !== 'parsed') && <>Some manifests were parsed partially or are unsupported — see coverage below.</>}
          </Callout>
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
        <Stat label="Verified vulnerabilities" value={s.vulnerabilities} icon={<Bug size={16} />}
          hint={<>in {s.vulnerable_packages} package(s) · {s.known_exploited} known-exploited</>} tone={s.vulnerabilities ? 'text-sev-high' : 'text-ok'} />
        <Stat label="Suspicious signals" value={s.suspicious_signals} icon={<Eye size={16} />} hint="heuristic, needs review" />
        <Stat label="Dependencies" value={s.packages} icon={<Layers size={16} />} hint={<>{s.direct} direct · {s.transitive} transitive · {s.components} component(s)</>} />
        <Stat label="Not verified" value={s.unverified_packages} icon={<Database size={16} />} hint="no intelligence / no exact version" tone={s.unverified_packages ? 'text-warn' : 'text-ink-100'} />
        <div className="card card-pad">
          <div className="flex items-center justify-between"><span className="label">Security gate</span><ShieldCheck size={16} className="text-ink-400" /></div>
          <div className={`mt-2 text-3xl font-semibold uppercase flex items-center gap-2 ${verdictTone}`}><VerdictIcon size={26} /> {pol.verdict}</div>
          <div className="mt-1 text-xs text-ink-400">{pol.violations.length} violation(s) · {pol.warning_count} warning(s)</div>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        <Card title="Verified vulnerabilities by severity" subtitle="Confirmed advisory matches only. Click a severity to filter." className="lg:col-span-2">
          <SeverityBar counts={s.severity} onPick={(k) => navigate(`/findings?kind=vulnerability&severity=${k}`)} />
          <div className="grid sm:grid-cols-3 gap-4 mt-6">
            <div>
              <div className="label mb-1">Confirmed vs. suspicious</div>
              <div className="text-sm text-ink-200"><b className="text-ink-100 tabular-nums">{s.verified_vulnerabilities}</b> confirmed advisory matches</div>
              <div className="text-sm text-ink-200"><b className="text-ink-100 tabular-nums">{s.suspicious_signals}</b> suspicious-package signals</div>
              <div className="text-sm text-ink-200"><b className="text-ink-100 tabular-nums">{s.integrity_signals + s.maintenance_signals}</b> integrity / maintenance</div>
              <div className="text-sm text-ink-200"><b className="text-ink-100 tabular-nums">{s.ci_findings + s.secret_findings + s.hygiene_findings}</b> CI, secret & hygiene</div>
            </div>
            <div>
              <div className="label mb-1">Fixability</div>
              <div className="text-sm text-ink-200"><b className="text-ink-100 tabular-nums">{s.fixable}</b> package(s) with a fix</div>
              <div className="text-sm text-ink-200"><b className="text-ok tabular-nums">{s.fix_verified}</b> fix verified clean by OSV</div>
              <Link to="/remediation" className="link text-xs mt-1 inline-block">Remediation center →</Link>
            </div>
            <div>
              <div className="label mb-1">Reachability of vulnerabilities</div>
              {reachRows.map(([k, v]) => (
                <div key={k} className="text-sm text-ink-200 flex justify-between"><span>{REACH_META[k]?.label ?? k}</span><b className="tabular-nums text-ink-100">{v}</b></div>
              ))}
            </div>
          </div>
        </Card>
        <Card title="Exposure by ecosystem" subtitle="Packages with ≥1 verified vulnerability / total">
          <HBars rows={Object.entries(s.by_ecosystem).map(([eco, e]) => ({ label: eco, value: e.vulnerable, sub: `of ${e.packages}${e.unverified ? `, ${e.unverified} unverified` : ''}` }))} />
        </Card>
      </div>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        <Card title="Top remediation priorities" subtitle="Ranked by explainable priority score" className="lg:col-span-2" pad={false}>
          <ul className="divide-y divide-ink-800">
            {s.top_priorities.map((t) => {
              const l = t.package_id ? labelFor(t.package_id) : null
              return (
                <li key={t.id}>
                  <button className="w-full text-left px-5 py-3 hover:bg-ink-800/60 flex items-center gap-3" onClick={() => setOpen(t.id)}>
                    <PriorityPill bucket={t.bucket} value={t.priority} />
                    <SeverityBadge s={t.severity} />
                    <span className="flex-1 min-w-0">
                      <span className="block text-sm text-ink-100 truncate">{t.title}</span>
                      <span className="block text-xs text-ink-400 mono">{l ? `${l.name}@${l.version ?? '?'}` : ''}</span>
                    </span>
                    <KindBadge k={t.kind} />
                    <StateBadge s={t.remediation} />
                  </button>
                </li>
              )
            })}
          </ul>
        </Card>
        <Card title="Vulnerability trend" subtitle={`Verified vulnerabilities across scans of ${r.scan.source_name}`}>
          <TrendLine points={trend} label="vulnerabilities" />
          <Link to="/history" className="link text-xs">Compare scans →</Link>
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <Card title="Data freshness & provenance" subtitle="Where every fact came from">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-ink-700"><th className="table-head py-1.5">Provider</th><th className="table-head">Status</th><th className="table-head text-right">Live</th><th className="table-head text-right">Cache</th><th className="table-head text-right">Stale/fixture</th><th className="table-head text-right">Unavailable</th></tr></thead>
            <tbody>
              {r.providers.map((p) => (
                <tr key={p.name} className="border-b border-ink-800">
                  <td className="py-1.5 text-ink-100" title={p.purpose}>{p.label}</td>
                  <td><span className={`chip ${p.status === 'ok' ? 'bg-ok/10 text-ok' : p.status === 'degraded' ? 'bg-warn/10 text-warn' : p.status === 'failed' ? 'bg-bad/10 text-bad' : 'bg-ink-700 text-ink-300'}`}>{p.status}</span></td>
                  <td className="text-right tabular-nums">{p.live_calls}</td><td className="text-right tabular-nums">{p.cache_hits}</td>
                  <td className="text-right tabular-nums">{p.stale_hits + p.fixture_hits}</td><td className={`text-right tabular-nums ${p.misses ? 'text-warn' : ''}`}>{p.misses}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="text-xs text-ink-400 mt-3 flex items-center gap-2 flex-wrap">
            OSV data from {fmtDate(s.data_freshness.oldest)} to {fmtDate(s.data_freshness.newest)} ({ago(s.data_freshness.newest)})
            {r.scan.offline && <OriginBadge o="fixture" />}
          </div>
        </Card>
        <Card title="Scanner coverage" subtitle={`${r.coverage.source_index.files_scanned} source file(s) analysed for reachability`}>
          <ul className="space-y-1.5 text-sm">
            {r.coverage.outcomes.map((o, i) => (
              <li key={i} className="flex items-start gap-2">
                {o.status === 'parsed' ? <CheckCircle2 size={15} className="text-ok mt-0.5 shrink-0" /> : o.status === 'partial' ? <AlertTriangle size={15} className="text-warn mt-0.5 shrink-0" /> : <ShieldAlert size={15} className="text-bad mt-0.5 shrink-0" />}
                <div className="min-w-0">
                  <span className="mono text-xs text-ink-100">{o.file}</span> <span className="text-xs text-ink-400">· {o.parser} · {o.status} · {o.packages} pkg</span>
                  {o.limitations.length > 0 && <div className="text-xs text-ink-400">{o.limitations[0]}</div>}
                </div>
              </li>
            ))}
          </ul>
          {r.coverage.input.rejected.length > 0 && (
            <div className="mt-3 text-xs text-warn">{r.coverage.input.rejected.length} unsafe archive entr{r.coverage.input.rejected.length > 1 ? 'ies were' : 'y was'} rejected (traversal/symlink/bomb protection).</div>
          )}
        </Card>
      </div>

      <Drawer open={!!open} onClose={() => setOpen(null)} title={<span className="text-sm text-ink-300">Finding detail</span>}>
        {open && <FindingDetail findingId={open} />}
      </Drawer>
    </div>
  )
}
