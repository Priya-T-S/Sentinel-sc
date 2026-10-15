import { Activity, Bot, Boxes, ClipboardList, GitBranch, History, LayoutDashboard, Package, Radar, Settings, Wrench } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link, useRouter } from '../router'
import { useScan } from '../state'
import { ago } from './ui'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/scan', label: 'Scan workspace', icon: Radar },
  { to: '/graph', label: 'Attack graph', icon: GitBranch },
  { to: '/findings', label: 'Findings', icon: ClipboardList },
  { to: '/package', label: 'Package intel', icon: Package },
  { to: '/remediation', label: 'Remediation', icon: Wrench },
  { to: '/agents', label: 'Agents', icon: Bot },
  { to: '/history', label: 'History & compare', icon: History },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function Layout({ children }: { children: ReactNode }) {
  const { path } = useRouter()
  const { scans, scanId, setScanId, result } = useScan()
  const completed = scans.filter((s) => s.status === 'completed')
  const osv = result?.providers.find((p) => p.name === 'osv')
  return (
    <div className="min-h-full flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:p-2 focus:bg-ink-800 focus:rounded">Skip to content</a>
      <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-ink-700 bg-ink-950/60 sticky top-0 h-screen">
        <div className="px-5 py-5 flex items-center gap-2.5">
          <svg viewBox="0 0 32 32" className="h-8 w-8" aria-hidden><path d="M16 2 4 7v8c0 7.2 5.1 13.4 12 15 6.9-1.6 12-7.8 12-15V7z" fill="#0b1220" stroke="#38bdf8" strokeWidth="2" /><circle cx="16" cy="15" r="4" fill="#38bdf8" /></svg>
          <div>
            <div className="text-sm font-bold tracking-wide text-ink-100">SENTINEL<span className="text-accent">-SC</span></div>
            <div className="text-[10px] uppercase tracking-[0.14em] text-ink-400">Supply-chain intelligence</div>
          </div>
        </div>
        <nav className="flex-1 px-3 space-y-0.5" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon }) => {
            const active = to === '/' ? path === '/' : path.startsWith(to)
            return (
              <Link key={to} to={to} aria-current={active ? 'page' : undefined}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${active ? 'bg-accent/10 text-ink-100 ring-1 ring-accent/30' : 'text-ink-300 hover:bg-ink-800 hover:text-ink-100'}`}>
                <Icon size={16} className={active ? 'text-accent' : ''} /> {label}
              </Link>
            )
          })}
        </nav>
        <div className="m-3 rounded-lg border border-ink-700 bg-ink-850 p-3 text-xs space-y-1">
          <div className="flex items-center gap-1.5 text-ink-300"><Activity size={13} /> Intelligence</div>
          {result ? (
            <>
              <div className="text-ink-100">{result.scan.offline ? 'Offline · cached/fixture data' : `OSV ${osv?.status ?? '—'}`}</div>
              <div className="text-ink-400">Data as of {ago(osv?.newest_data ?? null)}</div>
            </>
          ) : <div className="text-ink-400">No scan selected</div>}
        </div>
      </aside>
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="sticky top-0 z-30 border-b border-ink-700 bg-ink-900/90 backdrop-blur">
          <div className="flex items-center gap-3 px-4 md:px-8 h-14">
            <nav className="md:hidden flex gap-1 overflow-x-auto scrollbar-thin" aria-label="Main mobile">
              {NAV.map(({ to, icon: Icon, label }) => (
                <Link key={to} to={to} aria-label={label} className={`p-2 rounded-lg ${path === to ? 'bg-accent/10 text-accent' : 'text-ink-300'}`}><Icon size={16} /></Link>
              ))}
            </nav>
            <div className="flex-1" />
            <label className="hidden sm:flex items-center gap-2 text-xs text-ink-400">
              <Boxes size={14} /> Scan
              <select className="input py-1.5 max-w-[22rem]" value={scanId ?? ''} onChange={(e) => setScanId(e.target.value || null)} aria-label="Select scan">
                {!completed.length && <option value="">No completed scans</option>}
                {completed.map((s) => (
                  <option key={s.id} value={s.id}>{s.source_name} · {new Date(s.created_at * 1000).toLocaleString()} · {s.summary?.vulnerabilities ?? 0} vulns</option>
                ))}
              </select>
            </label>
            {result && (
              <span className={`chip ${result.scan.status === 'complete' ? 'bg-ok/10 text-ok' : 'bg-warn/10 text-warn'}`} title="Partial = some inputs or intelligence could not be fully verified">
                {result.scan.status}
              </span>
            )}
            {result?.scan.offline && <span className="chip bg-fuchsia-400/10 text-fuchsia-300">offline</span>}
          </div>
        </header>
        <main id="main" className="flex-1 px-4 md:px-8 py-6 max-w-[1500px] w-full mx-auto">{children}</main>
      </div>
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
      <div>
        <h1 className="text-xl font-semibold text-ink-100 tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-ink-400 mt-1 max-w-3xl">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
    </div>
  )
}
