import { AlertTriangle, Check, ChevronRight, Copy, Info, Loader2, ShieldQuestion, X } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { Severity } from '../types'

export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
export const SEV_STYLE: Record<string, { bg: string; text: string; ring: string; hex: string }> = {
  critical: { bg: 'bg-sev-critical/15', text: 'text-sev-critical', ring: 'ring-sev-critical/40', hex: '#f43f5e' },
  high: { bg: 'bg-sev-high/15', text: 'text-sev-high', ring: 'ring-sev-high/40', hex: '#fb923c' },
  medium: { bg: 'bg-sev-medium/15', text: 'text-sev-medium', ring: 'ring-sev-medium/40', hex: '#facc15' },
  low: { bg: 'bg-sev-low/15', text: 'text-sev-low', ring: 'ring-sev-low/40', hex: '#60a5fa' },
  info: { bg: 'bg-ink-600/40', text: 'text-ink-300', ring: 'ring-ink-500/40', hex: '#94a3b8' },
  unknown: { bg: 'bg-ink-600/40', text: 'text-ink-300', ring: 'ring-ink-500/40', hex: '#64748b' },
}

export function SeverityBadge({ s, className = '' }: { s: Severity | string | null | undefined; className?: string }) {
  const st = SEV_STYLE[s || 'unknown'] || SEV_STYLE.unknown
  return <span className={`chip ${st.bg} ${st.text} uppercase tracking-wide ${className}`}>{s || 'unknown'}</span>
}

const KIND_LABEL: Record<string, string> = {
  vulnerability: 'Verified vuln', suspicious: 'Suspicious', integrity: 'Integrity', maintenance: 'Maintenance',
  hygiene: 'Hygiene', secret: 'Secret', ci: 'CI/CD',
}
export function KindBadge({ k }: { k: string }) {
  const cls = k === 'vulnerability' ? 'bg-accent/15 text-accent' : k === 'suspicious' ? 'bg-fuchsia-400/15 text-fuchsia-300'
    : k === 'secret' ? 'bg-rose-400/15 text-rose-300' : k === 'ci' ? 'bg-violet-400/15 text-violet-300' : 'bg-ink-600/50 text-ink-200'
  return <span className={`chip ${cls}`}>{KIND_LABEL[k] || k}</span>
}

export const REACH_META: Record<string, { label: string; cls: string; rank: number }> = {
  symbol_call: { label: 'Call-site evidence', cls: 'bg-sev-critical/15 text-sev-critical', rank: 5 },
  imported: { label: 'Imported', cls: 'bg-sev-high/15 text-sev-high', rank: 4 },
  transitive_imported: { label: 'Via imported dep', cls: 'bg-sev-medium/15 text-sev-medium', rank: 3 },
  unknown: { label: 'Unknown', cls: 'bg-ink-600/50 text-ink-300', rank: 2 },
  transitive: { label: 'Transitive only', cls: 'bg-sev-low/15 text-sev-low', rank: 1 },
  declared_not_imported: { label: 'Not imported', cls: 'bg-ok/10 text-ok', rank: 0 },
}
export function ReachBadge({ level }: { level?: string }) {
  const m = REACH_META[level || 'unknown'] || REACH_META.unknown
  return <span className={`chip ${m.cls}`}>{m.label}</span>
}

export const STATE_META: Record<string, { label: string; cls: string }> = {
  safe_candidate: { label: 'Safe candidate', cls: 'bg-ok/15 text-ok' },
  requires_review: { label: 'Requires review', cls: 'bg-warn/15 text-warn' },
  no_verified_fix: { label: 'No verified fix', cls: 'bg-bad/15 text-bad' },
  insufficient_information: { label: 'Insufficient info', cls: 'bg-ink-600/50 text-ink-300' },
}
export function StateBadge({ s }: { s?: string | null }) {
  if (!s) return <span className="text-ink-400">—</span>
  const m = STATE_META[s] || { label: s, cls: 'bg-ink-600/50 text-ink-300' }
  return <span className={`chip ${m.cls}`}>{m.label}</span>
}

export function FixConfBadge({ c }: { c?: string | null }) {
  if (!c) return null
  const cls = c === 'verified' ? 'bg-ok/15 text-ok' : c === 'candidate' ? 'bg-warn/15 text-warn' : 'bg-ink-600/50 text-ink-300'
  const label = c === 'verified' ? 'Fix verified' : c === 'candidate' ? 'Candidate fix' : 'Unverified fix'
  return <span className={`chip ${cls}`} title={c === 'verified' ? 'OSV reports no known advisories for the proposed version' : c === 'candidate' ? 'Taken from advisory data; not re-checked or other advisories remain' : 'No authoritative fix data'}>{label}</span>
}

export function OriginBadge({ o }: { o?: string | null }) {
  if (!o) return null
  const cls = o === 'live' ? 'bg-ok/10 text-ok' : o === 'cache' ? 'bg-accent/10 text-accent' : o === 'fixture' ? 'bg-fuchsia-400/10 text-fuchsia-300'
    : o === 'stale' ? 'bg-warn/10 text-warn' : o === 'computed' ? 'bg-ink-600/40 text-ink-300' : 'bg-bad/10 text-bad'
  return <span className={`chip ${cls}`}>{o}</span>
}

export function PriorityPill({ bucket, value }: { bucket?: string; value?: number | null }) {
  const cls = bucket === 'P1' ? 'bg-sev-critical text-ink-950' : bucket === 'P2' ? 'bg-sev-high text-ink-950' : bucket === 'P3' ? 'bg-sev-medium/80 text-ink-950' : bucket === 'P4' ? 'bg-ink-600 text-ink-100' : 'bg-ink-700 text-ink-300'
  return (
    <span className={`chip ${cls} tabular-nums`} title="Remediation priority (see 'Why this score?')">
      {bucket || '—'}{value != null && <span className="opacity-80 font-medium">{Math.round(value)}</span>}
    </span>
  )
}

export function ScoreBar({ value, label, color = '#38bdf8' }: { value: number | null | undefined; label: string; color?: string }) {
  return (
    <div>
      <div className="flex justify-between text-xs mb-1"><span className="text-ink-300">{label}</span>
        <span className="tabular-nums text-ink-100 font-semibold">{value == null ? 'Unknown' : Math.round(value)}</span></div>
      <div className="h-1.5 rounded-full bg-ink-700 overflow-hidden">
        {value != null && <div className="h-full rounded-full" style={{ width: `${Math.max(2, Math.min(100, value))}%`, background: color }} />}
      </div>
    </div>
  )
}

export function Card({ title, actions, children, className = '', pad = true, subtitle }: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`card min-w-0 ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-3 border-b border-ink-700/70">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink-100">{title}</h2>}
            {subtitle && <p className="text-xs text-ink-400 mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={pad ? 'card-pad' : ''}>{children}</div>
    </section>
  )
}

export function Stat({ label, value, hint, tone, icon }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string; icon?: ReactNode }) {
  return (
    <div className="card card-pad min-w-0">
      <div className="flex items-center justify-between"><span className="label">{label}</span>{icon && <span className="text-ink-400">{icon}</span>}</div>
      <div className={`mt-2 text-3xl font-semibold tabular-nums tracking-tight ${tone || 'text-ink-100'}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-400">{hint}</div>}
    </div>
  )
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-ink-400 text-sm" role="status" aria-live="polite">
      <Loader2 className="animate-spin" size={16} /> {label}…
    </div>
  )
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2 animate-pulse" aria-hidden>
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="h-9 rounded-lg bg-ink-800" />)}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="card card-pad border-bad/40 flex items-start gap-3" role="alert">
      <AlertTriangle className="text-bad shrink-0 mt-0.5" size={18} />
      <div className="flex-1">
        <div className="text-sm font-semibold text-ink-100">Something went wrong</div>
        <div className="text-sm text-ink-300 mt-0.5">{message}</div>
      </div>
      {onRetry && <button className="btn-ghost" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function EmptyState({ title, body, action, icon }: { title: string; body?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center text-center py-14 px-6">
      <div className="h-12 w-12 rounded-full bg-ink-800 border border-ink-700 flex items-center justify-center text-ink-400 mb-4">
        {icon || <ShieldQuestion size={22} />}
      </div>
      <h3 className="text-base font-semibold text-ink-100">{title}</h3>
      {body && <div className="text-sm text-ink-400 mt-1 max-w-md">{body}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}

export function Callout({ tone = 'info', children, title }: { tone?: 'info' | 'warn' | 'bad' | 'ok'; children: ReactNode; title?: string }) {
  const map = { info: 'border-accent/30 bg-accent/5 text-accent', warn: 'border-warn/30 bg-warn/5 text-warn', bad: 'border-bad/30 bg-bad/5 text-bad', ok: 'border-ok/30 bg-ok/5 text-ok' }
  return (
    <div className={`rounded-lg border px-3.5 py-2.5 text-sm flex gap-2.5 ${map[tone]}`}>
      <Info size={16} className="shrink-0 mt-0.5" />
      <div className="text-ink-200">{title && <div className="font-semibold text-ink-100 mb-0.5">{title}</div>}{children}</div>
    </div>
  )
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      className="inline-flex items-center gap-1 text-xs text-ink-300 hover:text-ink-100 px-1.5 py-1 rounded hover:bg-ink-700"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200) }).catch(() => undefined)
      }}
      aria-label={label}
    >
      {done ? <Check size={13} /> : <Copy size={13} />} {done ? 'Copied' : label}
    </button>
  )
}

export function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="mono text-[12px] leading-5 bg-ink-950 border border-ink-700 rounded-lg p-3 overflow-auto scrollbar-thin max-h-96">
      {diff.split('\n').map((l, i) => {
        const cls = l.startsWith('+++') || l.startsWith('---') ? 'text-ink-400' : l.startsWith('+') ? 'text-ok bg-ok/5' : l.startsWith('-') ? 'text-bad bg-bad/5' : l.startsWith('@@') ? 'text-accent' : 'text-ink-300'
        return <div key={i} className={`${cls} px-1 -mx-1`}>{l || ' '}</div>
      })}
    </pre>
  )
}

export function Drawer({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const prev = document.activeElement as HTMLElement | null
    ref.current?.focus()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => { window.removeEventListener('keydown', onKey); prev?.focus?.() }
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-ink-950/70 backdrop-blur-[2px]" onClick={onClose} />
      <div ref={ref} tabIndex={-1} className={`relative h-full w-full ${wide ? 'max-w-4xl' : 'max-w-3xl'} bg-ink-900 border-l border-ink-700 shadow-2xl overflow-y-auto scrollbar-thin fade-in focus:outline-none`}>
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 px-6 py-4 bg-ink-900/95 backdrop-blur border-b border-ink-700">
          <div className="min-w-0">{title}</div>
          <button className="p-1.5 rounded-lg hover:bg-ink-750 text-ink-300" onClick={onClose} aria-label="Close panel"><X size={18} /></button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { key: T; label: ReactNode }[]; value: T; onChange: (k: T) => void }) {
  return (
    <div className="flex gap-1 border-b border-ink-700 mb-4 overflow-x-auto scrollbar-thin" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={value === t.key} onClick={() => onChange(t.key)}
          className={`px-3 py-2 text-sm -mb-px border-b-2 transition-colors whitespace-nowrap ${value === t.key ? 'border-accent text-ink-100' : 'border-transparent text-ink-400 hover:text-ink-200'}`}>
          {t.label}
        </button>
      ))}
    </div>
  )
}

export function PathView({ path, labels, highlightLast = true }: { path: string[]; labels: (id: string) => { name: string; version?: string | null; root?: boolean }; highlightLast?: boolean }) {
  return (
    <div className="flex flex-wrap items-center gap-1 text-xs">
      {path.map((id, i) => {
        const l = labels(id)
        const last = i === path.length - 1
        return (
          <span key={id + i} className="inline-flex items-center gap-1">
            <span className={`mono rounded-md px-1.5 py-0.5 border ${l.root ? 'border-accent/40 bg-accent/10 text-accent' : last && highlightLast ? 'border-sev-critical/50 bg-sev-critical/10 text-sev-critical' : 'border-ink-600 bg-ink-800 text-ink-200'}`}>
              {l.name}{l.version ? <span className="opacity-60">@{l.version}</span> : null}
            </span>
            {!last && <ChevronRight size={12} className="text-ink-500" />}
          </span>
        )
      })}
    </div>
  )
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
      {items.map(([k, v], i) => (
        <div key={i} className="contents"><dt className="text-ink-400">{k}</dt><dd className="text-ink-100 min-w-0 break-words">{v ?? <span className="text-ink-500">unknown</span>}</dd></div>
      ))}
    </dl>
  )
}

export function fmtDate(v?: string | number | null): string {
  if (v == null || v === '') return '—'
  const d = typeof v === 'number' ? new Date(v * 1000) : new Date(v)
  if (isNaN(d.getTime())) return String(v)
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export function ago(v?: string | number | null): string {
  if (v == null) return '—'
  const d = typeof v === 'number' ? v * 1000 : new Date(v).getTime()
  const s = (Date.now() - d) / 1000
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}

/** Only allow http(s) links from untrusted data. */
export function safeHref(u?: string | null): string | undefined {
  if (!u) return undefined
  try {
    const p = new URL(u)
    return p.protocol === 'https:' || p.protocol === 'http:' ? p.toString() : undefined
  } catch {
    return undefined
  }
}

export function ExtLink({ href, children }: { href?: string | null; children: ReactNode }) {
  const h = safeHref(href)
  if (!h) return <span>{children}</span>
  return <a className="link break-all" href={h} target="_blank" rel="noopener noreferrer">{children}</a>
}
