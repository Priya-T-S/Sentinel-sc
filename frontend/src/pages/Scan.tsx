import { CheckCircle2, CircleDashed, FileArchive, GitBranch, GitPullRequest, Loader2, Play, Square, UploadCloud, XCircle } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { PageHeader } from '../components/Layout'
import { Callout, Card, ErrorState, fmtDate } from '../components/ui'
import { useRouter } from '../router'
import { useScan } from '../state'
import type { ScanStatus } from '../types'

const AGENT_LABEL: Record<string, string> = { orchestrator: 'Orchestrator', vuln_intel: 'Vuln intel', package_trust: 'Package trust', reachability: 'Reachability', remediation: 'Remediation', reviewer: 'Reviewer' }

export function ScanPage() {
  const { setScanId, refreshScans, scans, reloadResult } = useScan()
  const { navigate } = useRouter()
  const [active, setActive] = useState<string | null>(null)
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [offline, setOffline] = useState(false)
  const [drag, setDrag] = useState(false)
  const [busy, setBusy] = useState(false)
  const [ghUrl, setGhUrl] = useState('')
  const [ghRef, setGhRef] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  // resume a running scan after navigation
  useEffect(() => {
    if (active) return
    const running = scans.find((s) => s.status === 'running' || s.status === 'queued')
    if (running) setActive(running.id)
  }, [scans, active])

  useEffect(() => {
    if (!active) return
    let stop = false
    const poll = async () => {
      try {
        const st = await api.get<ScanStatus>(`/api/scans/${active}`)
        if (stop) return
        setStatus(st)
        if (st.status === 'queued' || st.status === 'running') setTimeout(poll, 600)
        else {
          await refreshScans()
          if (st.status === 'completed') { setScanId(active); reloadResult() }
        }
      } catch (e) {
        if (!stop) setError((e as Error).message)
      }
    }
    poll()
    return () => { stop = true }
  }, [active, refreshScans, setScanId, reloadResult])

  const start = useCallback(async (fn: () => Promise<{ scan_id: string }>) => {
    setError(null); setStatus(null); setBusy(true)
    try {
      const r = await fn()
      setActive(r.scan_id)
      refreshScans()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }, [refreshScans])

  const upload = (file: File) => start(() => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('offline', String(offline))
    return api.upload('/api/scans', fd)
  })

  const running = status && (status.status === 'queued' || status.status === 'running')
  const stages = status?.progress?.stages || []
  return (
    <div className="fade-in">
      <PageHeader title="Scan workspace" subtitle="Scan a repository archive, a single lockfile/manifest, or a CycloneDX SBOM. Files are parsed locally — no code is installed or executed." />
      <div className="grid lg:grid-cols-5 gap-4">
        <div className="lg:col-span-3 space-y-4">
          <Card title="Preloaded demo project" subtitle="acme-orders-api: real vulnerable npm + PyPI pins, a transitive chain through express, a synthetic typosquat fixture, and risky CI config.">
            <div className="flex flex-wrap items-center gap-3">
              <button className="btn-primary text-base px-5 py-2.5" disabled={busy || !!running} onClick={() => start(() => api.post(`/api/demo/scan?offline=${offline}`))}>
                <Play size={17} /> Scan demo project
              </button>
              <button className="btn-ghost" disabled={busy || !!running} onClick={async () => {
                setError(null); setBusy(true)
                try {
                  const r = await api.post<{ base_scan_id: string; head_scan_id: string }>(`/api/demo/pr-review?offline=${offline}`)
                  await refreshScans()
                  navigate(`/history?base=${r.base_scan_id}&head=${r.head_scan_id}`)
                } catch (e) { setError((e as Error).message) } finally { setBusy(false) }
              }}><GitPullRequest size={16} /> Run PR-review demo</button>
              <label className="flex items-center gap-2 text-sm text-ink-300 cursor-pointer">
                <input type="checkbox" className="accent-sky-400 h-4 w-4" checked={offline} onChange={(e) => setOffline(e.target.checked)} />
                Offline mode (use cached / versioned fixture intelligence only)
              </label>
            </div>
          </Card>

          <Card title={<span className="flex items-center gap-2"><GitBranch size={15} /> Scan a public GitHub repository</span>}
            subtitle="Paste a repository link. The exact commit is resolved and its archive downloaded safely — nothing is cloned, installed or run.">
            <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => {
              e.preventDefault()
              if (!ghUrl.trim()) return
              start(() => api.post('/api/scans/github', { url: ghUrl.trim(), ref: ghRef.trim() || null, offline }))
            }}>
              <label className="grid gap-1 flex-1 min-w-[16rem]"><span className="label">Repository URL</span>
                <input className="input" placeholder="https://github.com/owner/repo" value={ghUrl} onChange={(e) => setGhUrl(e.target.value)} aria-label="GitHub repository URL" /></label>
              <label className="grid gap-1 w-44"><span className="label">Branch / tag / commit (optional)</span>
                <input className="input" placeholder="default branch" value={ghRef} onChange={(e) => setGhRef(e.target.value)} aria-label="Branch, tag or commit" /></label>
              <button type="submit" className="btn-primary" disabled={busy || !!running || !ghUrl.trim()}><GitBranch size={15} /> Scan repository</button>
            </form>
            <p className="text-xs text-ink-400 mt-2">Public github.com repositories only · archive limit 50 MB · GitHub allows 60 anonymous lookups per hour · not available in offline mode.</p>
          </Card>

          <Card title="Upload">
            <div
              className={`rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors cursor-pointer ${drag ? 'border-accent bg-accent/5' : 'border-ink-600 hover:border-ink-500'}`}
              onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) upload(f) }}
              onClick={() => inputRef.current?.click()}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inputRef.current?.click() } }}
              role="button" tabIndex={0} aria-label="Upload a repository archive, lockfile or SBOM"
            >
              <UploadCloud className="mx-auto text-accent" size={30} />
              <div className="mt-3 text-sm text-ink-100 font-medium">Drop a .zip of your repository, a lockfile, or a CycloneDX SBOM</div>
              <div className="mt-1 text-xs text-ink-400">package-lock.json · yarn.lock · pnpm-lock.yaml · requirements.txt · poetry.lock · Pipfile.lock · go.mod · Cargo.lock · pom.xml · packages.lock.json · *.cdx.json — max 50 MB</div>
              <input ref={inputRef} type="file" className="hidden" accept=".zip,.json,.lock,.txt,.toml,.yaml,.xml,.mod,.csproj,.lockfile,.gradle,.kts"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = '' }} />
            </div>
            <p className="text-xs text-ink-400 mt-3"><b className="text-ink-300">Local-directory scanning</b> is available through the CLI: <code className="mono">python -m sentinel scan ./path</code></p>
          </Card>

          {error && <ErrorState message={error} />}

          {status && (
            <Card title={<span className="flex items-center gap-2"><FileArchive size={15} /> {status.source_name}</span>}
              subtitle={`Scan ${status.id} · started ${fmtDate(status.created_at)}`}
              actions={running ? <button className="btn-danger" onClick={() => api.post(`/api/scans/${status.id}/cancel`).catch((e) => setError(e.message))}><Square size={14} /> Cancel</button> : undefined}>
              <div className="mb-4">
                <div className="flex justify-between text-xs mb-1.5"><span className="text-ink-300">{running ? 'Scanning…' : status.status}</span>
                  <span className="tabular-nums text-ink-100">{Math.round(status.progress?.percent ?? (status.status === 'completed' ? 100 : 0))}%</span></div>
                <div className="h-2 rounded-full bg-ink-700 overflow-hidden" role="progressbar" aria-valuenow={status.progress?.percent ?? 0} aria-valuemin={0} aria-valuemax={100}>
                  <div className="h-full bg-accent transition-all duration-500" style={{ width: `${status.progress?.percent ?? (status.status === 'completed' ? 100 : 0)}%` }} />
                </div>
              </div>
              <ol className="space-y-1.5" aria-live="polite">
                {stages.map((st) => (
                  <li key={st.key} className="flex items-center gap-2.5 text-sm">
                    {st.status === 'skipped' ? <CircleDashed size={15} className="text-ink-500" /> : st.status === 'done' ? <CheckCircle2 size={15} className="text-ok" /> : st.status === 'running' ? <Loader2 size={15} className="text-accent animate-spin" /> : <CircleDashed size={15} className="text-ink-500" />}
                    <span className={st.status === 'pending' ? 'text-ink-500' : 'text-ink-100'}>{st.label}</span>
                    {st.agent && <span className="chip bg-ink-750 text-ink-300">{AGENT_LABEL[st.agent] || st.agent}</span>}
                    {st.detail && <span className="text-xs text-ink-400 truncate">— {st.detail}</span>}
                  </li>
                ))}
              </ol>
              {status.status === 'completed' && (
                <div className="mt-4 flex items-center gap-3 flex-wrap">
                  <span className={`chip ${status.summary?.status === 'complete' ? 'bg-ok/15 text-ok' : 'bg-warn/15 text-warn'}`}>{status.summary?.status === 'complete' ? 'Complete' : 'Partial success'}</span>
                  <span className="text-sm text-ink-300">{status.summary?.vulnerabilities} verified vulnerabilities · {status.summary?.suspicious_signals} suspicious signals · {status.summary?.unverified_packages} not verified</span>
                  <button className="btn-primary" onClick={() => navigate('/')}>View results</button>
                </div>
              )}
              {(status.status === 'failed' || status.status === 'cancelled') && (
                <div className="mt-4 flex items-center gap-2 text-sm text-bad"><XCircle size={16} /> {status.status === 'failed' ? `Scan failed: ${status.error ?? 'unknown error'}` : `Cancelled${status.error ? ` — ${status.error}` : ''}`}</div>
              )}
            </Card>
          )}
        </div>

        <div className="lg:col-span-2 space-y-4">
          <Card title="What leaves your machine">
            <ul className="text-sm text-ink-300 space-y-2 list-disc pl-4">
              <li><b className="text-ink-100">OSV.dev</b>: ecosystem, package name and exact version.</li>
              <li><b className="text-ink-100">npm / PyPI registries</b>: package names (public metadata).</li>
              <li><b className="text-ink-100">OpenSSF Scorecard</b>: public GitHub repo paths of dependencies.</li>
              <li><b className="text-ink-100">CISA KEV / FIRST EPSS</b>: CVE identifiers (KEV is downloaded whole).</li>
            </ul>
            <Callout tone="ok">Source code, file contents, secrets, environment variables and repository names are never sent. Offline mode sends nothing.</Callout>
          </Card>
          <Card title="Safety controls on this input">
            <ul className="text-sm text-ink-300 space-y-1.5 list-disc pl-4">
              <li>Archives are read in memory — never extracted to disk.</li>
              <li>Path traversal, absolute paths and symlink entries are rejected.</li>
              <li>Decompression-bomb ratio, file count, size and depth limits.</li>
              <li>Package code is inspected as text only; nothing is installed or run.</li>
              <li>Scans are time-limited and can be cancelled.</li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  )
}
