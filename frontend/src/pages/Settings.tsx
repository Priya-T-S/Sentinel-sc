import { Activity, RefreshCcw, Save, ShieldCheck, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../api'
import { PageHeader } from '../components/Layout'
import { Callout, Card, CopyButton, ErrorState, Loading, Tabs, ago, fmtDate } from '../components/ui'
import { useApi } from '../hooks'
import { useScan } from '../state'
import type { PolicyResult } from '../types'

type Tab = 'policy' | 'providers' | 'privacy' | 'coverage' | 'scoring' | 'ci' | 'events'

export function SettingsPage() {
  const [tab, setTab] = useState<Tab>(window.location.hash === '#scoring' ? 'scoring' : 'policy')
  return (
    <div className="fade-in">
      <PageHeader title="Settings" subtitle="Security-gate policy, intelligence providers, privacy controls and scanner limits." />
      <Tabs<Tab> value={tab} onChange={setTab} tabs={[
        { key: 'policy', label: 'Security gate policy' }, { key: 'providers', label: 'Providers & freshness' }, { key: 'privacy', label: 'Privacy & retention' },
        { key: 'coverage', label: 'Ecosystems & limits' }, { key: 'scoring', label: 'Scoring model' }, { key: 'ci', label: 'CI integration' }, { key: 'events', label: 'Security events' }]} />
      {tab === 'policy' && <PolicyTab />}
      {tab === 'providers' && <ProvidersTab />}
      {tab === 'privacy' && <PrivacyTab />}
      {tab === 'coverage' && <CoverageTab />}
      {tab === 'scoring' && <ScoringTab />}
      {tab === 'ci' && <CiTab />}
      {tab === 'events' && <EventsTab />}
    </div>
  )
}

type Pol = Record<string, unknown>
const SEVS = ['critical', 'high', 'medium', 'low', 'none']

function PolicyTab() {
  const { scanId } = useScan()
  const { data, loading, error, reload } = useApi<{ policy: Pol; default: Pol }>('/api/policy')
  const [pol, setPol] = useState<Pol | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [evalRes, setEvalRes] = useState<PolicyResult | null>(null)
  useEffect(() => { if (data) setPol(data.policy) }, [data])
  if (loading || !pol) return error ? <ErrorState message={error} onRetry={reload} /> : <Loading />
  const set = (k: string, v: unknown) => setPol({ ...pol, [k]: v })
  const save = async () => {
    setErr(null); setMsg(null)
    try { const r = await api.put<{ policy: Pol }>('/api/policy', { policy: pol }); setPol(r.policy); setMsg('Policy saved.') } catch (e) { setErr((e as Error).message) }
  }
  const evaluate = async () => {
    setErr(null)
    try { setEvalRes(await api.post<PolicyResult>(`/api/scans/${scanId}/policy`, { policy: pol })) } catch (e) { setErr((e as Error).message) }
  }
  const sel = (k: string, opts: string[], label: string, help: string) => (
    <label className="grid gap-1"><span className="text-sm text-ink-100">{label}</span><span className="text-xs text-ink-400">{help}</span>
      <select className="input max-w-xs" value={String(pol[k])} onChange={(e) => set(k, e.target.value)}>{opts.map((o) => <option key={o}>{o}</option>)}</select></label>
  )
  const bool = (k: string, label: string, help: string) => (
    <label className="flex items-start gap-3 cursor-pointer"><input type="checkbox" className="accent-sky-400 mt-1 h-4 w-4" checked={!!pol[k]} onChange={(e) => set(k, e.target.checked)} />
      <span><span className="text-sm text-ink-100 block">{label}</span><span className="text-xs text-ink-400">{help}</span></span></label>
  )
  const list = (k: string, label: string, help: string) => (
    <label className="grid gap-1"><span className="text-sm text-ink-100">{label}</span><span className="text-xs text-ink-400">{help}</span>
      <input className="input" value={(pol[k] as string[]).join(', ')} onChange={(e) => set(k, e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} /></label>
  )
  return (
    <div className="grid xl:grid-cols-[1fr_420px] gap-4">
      <Card title="Policy" subtitle="Deterministic and auditable: the same scan result and policy always produce the same verdict. AI is never involved."
        actions={<><button className="btn-ghost" onClick={() => data && setPol(data.default)}>Reset to defaults</button><button className="btn-primary" onClick={save}><Save size={15} /> Save</button></>}>
        <div className="grid md:grid-cols-2 gap-5">
          {sel('fail_on_vulnerability_severity', SEVS, 'Fail on verified vulnerabilities at or above', 'Only verified advisory matches can fail the gate.')}
          {sel('fail_min_confidence', ['low', 'medium', 'high'], 'Minimum assessment confidence to fail', 'Low-confidence matches only warn.')}
          {sel('warn_on_vulnerability_severity', SEVS, 'Warn on vulnerabilities at or above', '')}
          {sel('warn_on_signal_severity', SEVS, 'Warn on heuristic signals at or above', 'Suspicious, integrity, CI, secret and hygiene findings.')}
          {bool('fail_on_known_exploited', 'Fail on any known-exploited (CISA KEV) vulnerability', 'Regardless of severity threshold.')}
          {bool('fail_only_if_fix_available', 'Fail only when a fix exists', 'Avoids blocking builds on issues with no remediation.')}
          {bool('fail_on_intelligence_unavailable', 'Fail when intelligence is unavailable', 'Recommended. Prevents a provider outage from passing as "clean".')}
          {bool('fail_on_unverified_packages', 'Fail on packages without exact versions', 'Range-only dependencies cannot be matched.')}
          {bool('require_lockfile', 'Require lockfiles', 'Missing lockfile is a warning (or a failure with strict mode).')}
          {bool('strict_lockfile', 'Strict lockfile mode', 'Missing lockfile fails the gate.')}
          {bool('flag_unpinned', 'Flag unpinned / drifting dependencies', '')}
          {bool('ignore_dev_dependencies', 'Ignore dev/test dependencies', '')}
          <div className="md:col-span-2">{list('fail_on_signal_kinds', 'Heuristic signal kinds that fail the build', 'e.g. ci_pwn_request, secret_private_key, integrity_mismatch, scope_registry_mismatch')}</div>
          <div className="md:col-span-2">{list('ignored_advisories', 'Accepted risk: ignored advisory IDs', 'Explicit, auditable exceptions (GHSA/CVE IDs). Prefer fixing.')}</div>
          <div className="md:col-span-2">{list('disallowed_licenses', 'Disallowed licenses', 'Enforced only where reliable license metadata exists (registry/SBOM).')}</div>
        </div>
        {msg && <div className="mt-4"><Callout tone="ok">{msg}</Callout></div>}
        {err && <div className="mt-4"><ErrorState message={err} /></div>}
      </Card>
      <Card title="Evaluate against current scan" actions={<button className="btn-ghost" onClick={evaluate} disabled={!scanId}><ShieldCheck size={15} /> Evaluate</button>}>
        {!evalRes ? <p className="text-sm text-ink-400">Evaluate the unsaved policy above against the selected scan.</p> : (
          <div>
            <div className={`text-2xl font-semibold uppercase ${evalRes.verdict === 'fail' ? 'text-bad' : evalRes.verdict === 'warn' ? 'text-warn' : 'text-ok'}`}>{evalRes.verdict}</div>
            <div className="text-xs text-ink-400 mb-3">exit code {evalRes.exit_code} · {evalRes.violations.length} violation(s) · {evalRes.warning_count} warning(s)</div>
            <ul className="space-y-1.5 text-sm max-h-96 overflow-y-auto scrollbar-thin">
              {evalRes.violations.map((v, i) => <li key={i} className="text-bad"><span className="mono text-[11px] text-ink-400">[{v.rule}]</span> {v.package} {v.message}</li>)}
              {evalRes.warnings.slice(0, 40).map((v, i) => <li key={'w' + i} className="text-warn"><span className="mono text-[11px] text-ink-400">[{v.rule}]</span> {v.package} {v.message}</li>)}
            </ul>
          </div>
        )}
      </Card>
    </div>
  )
}

interface ProvidersResp { cache: { provider: string; origin: string; n: number; oldest: number; newest: number }[]; last_scan: null | { scan_id: string; finished_at: number; providers: { name: string; label: string; status: string; purpose: string; data_sent: string; errors: string[] }[] | null }; fixture: null | { created_at: string; entries: number; description: string } }

function ProvidersTab() {
  const { data, loading, error, reload } = useApi<ProvidersResp>('/api/providers')
  const [check, setCheck] = useState<Record<string, { ok: boolean; ms?: number; error?: string }> | null>(null)
  const [checking, setChecking] = useState(false)
  if (loading) return <Loading />
  if (error || !data) return <ErrorState message={error || ''} onRetry={reload} />
  return (
    <div className="grid lg:grid-cols-2 gap-4">
      <Card title="Provider health" actions={<button className="btn-ghost" disabled={checking} onClick={async () => { setChecking(true); try { setCheck(await api.post('/api/providers/check')) } finally { setChecking(false) } }}><Activity size={15} /> {checking ? 'Checking…' : 'Live check'}</button>}>
        <table className="w-full text-sm"><thead><tr className="border-b border-ink-700"><th className="table-head py-1.5">Provider</th><th className="table-head">Last scan</th><th className="table-head">Live check</th></tr></thead>
          <tbody>{(data.last_scan?.providers || []).map((p) => (
            <tr key={p.name} className="border-b border-ink-800 align-top">
              <td className="py-2"><div className="text-ink-100">{p.label}</div><div className="text-xs text-ink-400">{p.purpose}</div><div className="text-[11px] text-ink-500">Sends: {p.data_sent}</div></td>
              <td><span className="chip bg-ink-750 text-ink-200">{p.status}</span>{p.errors.length > 0 && <div className="text-[11px] text-warn mt-1">{p.errors[0]}</div>}</td>
              <td>{check ? (check[p.name] ? (check[p.name].ok ? <span className="text-ok text-xs">ok · {check[p.name].ms} ms</span> : <span className="text-bad text-xs">{check[p.name].error}</span>) : <span className="text-ink-500 text-xs">not probed</span>) : '—'}</td>
            </tr>))}</tbody></table>
        {!data.last_scan && <p className="text-sm text-ink-400">No completed scan yet.</p>}
      </Card>
      <Card title="Intelligence cache & offline fixture">
        <table className="w-full text-sm mb-4"><thead><tr className="border-b border-ink-700"><th className="table-head py-1.5">Provider</th><th className="table-head">Origin</th><th className="table-head text-right">Entries</th><th className="table-head">Oldest</th><th className="table-head">Newest</th></tr></thead>
          <tbody>{data.cache.map((c) => (
            <tr key={c.provider + c.origin} className="border-b border-ink-800"><td className="py-1.5">{c.provider}</td><td>{c.origin}</td><td className="text-right tabular-nums">{c.n}</td><td className="text-xs">{ago(c.oldest)}</td><td className="text-xs">{ago(c.newest)}</td></tr>))}</tbody></table>
        {data.fixture && <Callout title={`Versioned fixture · created ${fmtDate(data.fixture.created_at)} · ${data.fixture.entries} entries`}>{data.fixture.description}</Callout>}
      </Card>
    </div>
  )
}

function PrivacyTab() {
  const { refreshScans, setScanId } = useScan()
  const { data, loading, reload } = useApi<Record<string, unknown>>('/api/settings')
  const [s, setS] = useState<Record<string, unknown> | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  useEffect(() => { if (data) setS(data) }, [data])
  if (loading || !s) return <Loading />
  const save = async (patch: Record<string, unknown>) => { const r = await api.put<Record<string, unknown>>('/api/settings', patch); setS(r); setMsg('Saved.') }
  const toggle = (k: string, label: string, help: string) => (
    <label className="flex items-start gap-3 cursor-pointer"><input type="checkbox" className="accent-sky-400 mt-1 h-4 w-4" checked={!!s[k]} onChange={(e) => save({ [k]: e.target.checked })} />
      <span><span className="text-sm text-ink-100 block">{label}</span><span className="text-xs text-ink-400">{help}</span></span></label>
  )
  return (
    <div className="grid lg:grid-cols-2 gap-4">
      <Card title="Network & data sharing">
        <div className="space-y-4">
          {toggle('offline_mode', 'Offline mode (all scans)', 'No network calls. Uses cached and versioned fixture data, labelled with its age. Packages without data are shown as "Not verified".')}
          {toggle('enable_registry_metadata', 'Registry metadata (npm, PyPI)', 'Sends package names to fetch publish dates, maintainers, scripts and provenance metadata.')}
          {toggle('enable_scorecard', 'OpenSSF Scorecard', 'Sends public GitHub repository paths of direct dependencies.')}
          {toggle('enable_epss_kev', 'CISA KEV & FIRST EPSS', 'Downloads the KEV catalog; sends CVE identifiers to EPSS.')}
          <div className="border-t border-ink-700 pt-4 space-y-4">
            {toggle('ai_assistance', 'AI explanations (Claude, optional)', `Off by default. Sends evidence for the top findings (package names/versions, advisory text, paths, reachability levels, fix candidates) to Anthropic to get plain-language explanations. Never changes findings, scores or the verdict. ${s.ai_credential_configured ? 'Credential detected on the server.' : 'No ANTHROPIC_API_KEY on the server — this has no effect until one is set.'}`)}
            {toggle('ai_share_code_snippets', 'Include call-site code lines in AI requests', 'Off: only file names and line numbers are sent. On: the single source line of each cited call site is included.')}
          </div>
          <Callout tone="ok">Vulnerability matching (OSV) sends only ecosystem, package name and exact version. Source code, secrets and file contents never leave this machine.</Callout>
        </div>
      </Card>
      <Card title="Retention & deletion">
        <label className="grid gap-1 max-w-xs"><span className="text-sm text-ink-100">Keep scan history for (days, 0 = forever)</span>
          <input type="number" min={0} max={3650} className="input" value={Number(s.retention_days ?? 30)} onChange={(e) => setS({ ...s, retention_days: +e.target.value })} onBlur={() => save({ retention_days: Number(s.retention_days) })} /></label>
        <div className="flex flex-wrap gap-2 mt-5">
          <button className="btn-danger" onClick={async () => { if (window.confirm('Delete ALL scan history?')) { await api.del('/api/scans'); setScanId(null); await refreshScans(); setMsg('Scan history deleted.') } }}><Trash2 size={15} /> Delete all scans</button>
          <button className="btn-ghost" onClick={async () => { await api.del('/api/cache'); setMsg('Live intelligence cache cleared (fixture kept).'); reload() }}><Trash2 size={15} /> Clear intelligence cache</button>
          <button className="btn-ghost" onClick={async () => { const r = await api.post<{ removed_demo_scans: number }>('/api/demo/reset'); setScanId(null); await refreshScans(); setMsg(`Demo reset: ${r.removed_demo_scans} demo scan(s) removed, fixture reloaded.`) }}><RefreshCcw size={15} /> Reset demo dataset</button>
        </div>
        {msg && <div className="mt-4"><Callout tone="ok">{msg}</Callout></div>}
      </Card>
    </div>
  )
}

interface Meta { coverage: { ecosystem: string; file: string; status: string; notes: string }[]; limits: Record<string, number>; scoring: { doc: string; reachability_weights: Record<string, number>; scope_weights: Record<string, number> }; version: string }

function CoverageTab() {
  const { data, loading } = useApi<Meta>('/api/meta')
  if (loading || !data) return <Loading />
  return (
    <div className="grid xl:grid-cols-[1fr_380px] gap-4">
      <Card title="Supported ecosystems & files" subtitle="Unsupported files are detected and reported — never silently treated as a clean scan." pad={false}>
        <table className="w-full text-sm"><thead className="border-b border-ink-700"><tr><th className="table-head px-4 py-2">Ecosystem</th><th className="table-head px-3">File</th><th className="table-head px-3">Support</th><th className="table-head px-3">Notes</th></tr></thead>
          <tbody>{data.coverage.map((c, i) => (
            <tr key={i} className="border-b border-ink-800 align-top"><td className="px-4 py-2 text-ink-100">{c.ecosystem}</td><td className="px-3 mono text-xs">{c.file}</td>
              <td className="px-3"><span className={`chip ${c.status === 'full' ? 'bg-ok/10 text-ok' : c.status === 'partial' ? 'bg-warn/10 text-warn' : 'bg-bad/10 text-bad'}`}>{c.status}</span></td><td className="px-3 text-xs text-ink-300">{c.notes}</td></tr>))}</tbody></table>
      </Card>
      <Card title="Scan limits" subtitle={`Engine ${data.version}`}>
        <table className="w-full text-xs"><tbody>{Object.entries(data.limits).map(([k, v]) => (
          <tr key={k} className="border-b border-ink-800"><td className="py-1 text-ink-300">{k.replace(/_/g, ' ')}</td><td className="text-right mono text-ink-100">{k.includes('bytes') ? `${(v / 1048576).toFixed(1)} MB` : v}</td></tr>))}</tbody></table>
      </Card>
    </div>
  )
}

function ScoringTab() {
  const { data, loading } = useApi<Meta>('/api/meta')
  if (loading || !data) return <Loading />
  return (
    <Card title="Explainable risk model" subtitle="The exact text of the engine's scoring documentation (backend/sentinel/scoring.py)">
      <pre className="whitespace-pre-wrap text-sm text-ink-200 leading-6 mono">{data.scoring.doc}</pre>
    </Card>
  )
}

const WORKFLOW = `name: supply-chain-gate
on: [pull_request]
permissions:
  contents: read
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pin-to-commit-sha>
      - uses: actions/setup-python@<pin-to-commit-sha>
        with: { python-version: "3.12" }
      - run: pip install -r tools/sentinel-sc/backend/requirements.txt
      - name: SENTINEL-SC security gate
        run: python -m sentinel scan . --policy .sentinel-policy.json --json sentinel.json --sbom sbom.cdx.json
        working-directory: tools/sentinel-sc/backend   # adjust to where SENTINEL-SC lives
      - uses: actions/upload-artifact@<pin-to-commit-sha>
        if: always()
        with: { name: sentinel-report, path: "tools/sentinel-sc/backend/sentinel.json" }`

function CiTab() {
  return (
    <div className="grid lg:grid-cols-2 gap-4">
      <Card title="GitHub Actions" actions={<CopyButton text={WORKFLOW} />} subtitle="Full reusable workflow: ci/sentinel-gate.yml in this repository">
        <pre className="mono text-xs bg-ink-950 border border-ink-700 rounded-lg p-3 overflow-auto scrollbar-thin">{WORKFLOW}</pre>
      </Card>
      <Card title="CLI exit codes">
        <table className="w-full text-sm"><tbody>
          {[['0', 'Pass (or warnings only)'], ['1', 'Policy violation — fail the build'], ['2', 'Scan error / no supported input'], ['3', 'Warnings, with --strict-warn']].map(([c, d]) => (
            <tr key={c} className="border-b border-ink-800"><td className="py-1.5 mono text-accent w-12">{c}</td><td className="text-ink-200">{d}</td></tr>))}
        </tbody></table>
        <p className="text-xs text-ink-400 mt-3">Machine-readable outputs: <code className="mono">--json</code> (full result + gate), <code className="mono">--sbom</code> (CycloneDX 1.5 with VEX analysis), <code className="mono">--html</code>.</p>
      </Card>
    </div>
  )
}

function EventsTab() {
  const { data, loading, reload } = useApi<{ items: { ts: number; kind: string; detail: string }[] }>('/api/security-events')
  if (loading) return <Loading />
  return (
    <Card title="Security-relevant events" subtitle="Rejected uploads, CSRF/host violations, rate limiting, scan failures. Payloads and secrets are never logged." actions={<button className="btn-ghost" onClick={reload}><RefreshCcw size={14} /> Refresh</button>}>
      {!data?.items.length ? <p className="text-sm text-ink-400">No events recorded.</p> : (
        <table className="w-full text-sm"><tbody>{data.items.map((e, i) => (
          <tr key={i} className="border-b border-ink-800"><td className="py-1.5 text-xs text-ink-400 whitespace-nowrap pr-4">{fmtDate(e.ts)}</td><td className="mono text-xs text-warn pr-4">{e.kind}</td><td className="text-ink-300 text-xs">{e.detail}</td></tr>))}</tbody></table>
      )}
    </Card>
  )
}
