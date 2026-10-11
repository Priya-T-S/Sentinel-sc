import { Crosshair, Maximize2, Minus, Plus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { PageHeader } from '../components/Layout'
import { useScanGuard } from '../components/NoScan'
import { FindingDetail } from '../components/FindingDetail'
import { Callout, Drawer, ErrorState, FixConfBadge, KindBadge, Loading, PathView, ReachBadge, SEV_STYLE, SeverityBadge, StateBadge } from '../components/ui'
import { useApi } from '../hooks'
import { Link, useRouter } from '../router'
import { labelFor, useScan } from '../state'
import type { Finding, GraphEdge, GraphNode, PackageInfo, Plan } from '../types'

const NODE_W = 172, NODE_H = 34, COL_GAP = 92, ROW_GAP = 14
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0, unknown: 0 }

interface Laid { n: GraphNode; x: number; y: number; layer: number }

function layout(nodes: GraphNode[], edges: GraphEdge[]): { laid: Map<string, Laid>; width: number; height: number } {
  const parents = new Map<string, string[]>()
  const children = new Map<string, string[]>()
  for (const e of edges) {
    if (!parents.has(e.to)) parents.set(e.to, [])
    parents.get(e.to)!.push(e.from)
    if (!children.has(e.from)) children.set(e.from, [])
    children.get(e.from)!.push(e.to)
  }
  // layer = BFS depth from roots within the visible subgraph
  const layer = new Map<string, number>()
  const q: string[] = []
  for (const n of nodes) if (n.type === 'root') { layer.set(n.id, 0); q.push(n.id) }
  while (q.length) {
    const id = q.shift()!
    for (const c of children.get(id) || []) if (!layer.has(c)) { layer.set(c, layer.get(id)! + 1); q.push(c) }
  }
  for (const n of nodes) if (!layer.has(n.id)) layer.set(n.id, n.depth ?? 1)
  const layers: string[][] = []
  for (const n of nodes) { const l = layer.get(n.id)!; (layers[l] ||= []).push(n.id) }
  const byId = new Map(nodes.map((n) => [n.id, n]))
  // initial order: risk first, then name
  layers.forEach((ids) => ids.sort((a, b) => (SEV_RANK[byId.get(b)?.max_severity || ''] ?? -1) - (SEV_RANK[byId.get(a)?.max_severity || ''] ?? -1) || (byId.get(a)!.name || '').localeCompare(byId.get(b)!.name || '')))
  // barycenter sweeps to reduce edge crossings
  const pos = new Map<string, number>()
  const setPos = () => layers.forEach((ids) => ids?.forEach((id, i) => pos.set(id, i)))
  setPos()
  for (let sweep = 0; sweep < 4; sweep++) {
    for (let l = 1; l < layers.length; l++) {
      if (!layers[l]) continue
      const bc = (id: string) => { const ps = (parents.get(id) || []).filter((p) => layer.get(p) === l - 1); return ps.length ? ps.reduce((a, p) => a + (pos.get(p) ?? 0), 0) / ps.length : pos.get(id) ?? 0 }
      layers[l].sort((a, b) => bc(a) - bc(b))
      setPos()
    }
  }
  // Tall layers wrap into several sub-columns so the graph stays readable.
  const MAX_ROWS = 14
  const laid = new Map<string, Laid>()
  const subCols = layers.map((ids) => Math.max(1, Math.ceil((ids?.length || 0) / MAX_ROWS)))
  const rowsPer = layers.map((ids, l) => Math.ceil((ids?.length || 0) / subCols[l]))
  const height = Math.max(...rowsPer, 1) * (NODE_H + ROW_GAP) + 40
  let x0 = 20
  layers.forEach((ids, l) => {
    if (!ids) return
    const rows = rowsPer[l]
    const colH = rows * (NODE_H + ROW_GAP)
    const off = (height - colH) / 2
    ids.forEach((id, i) => {
      const sc = Math.floor(i / rows), row = i % rows
      laid.set(id, { n: byId.get(id)!, layer: l, x: x0 + sc * (NODE_W + 24), y: off + row * (NODE_H + ROW_GAP) })
    })
    x0 += subCols[l] * (NODE_W + 24) - 24 + COL_GAP
  })
  return { laid, width: x0 + 20 - COL_GAP, height }
}

export function GraphPage() {
  const guard = useScanGuard()
  const { scanId, result } = useScan()
  const { search } = useRouter()
  const [mode, setMode] = useState<'risky' | 'full'>('risky')
  const [minSev, setMinSev] = useState('any')
  const [eco, setEco] = useState('')
  const [maxDepth, setMaxDepth] = useState(12)
  const [ftype, setFtype] = useState<'all' | 'vuln' | 'signal'>('all')
  const [selected, setSelected] = useState<string | null>(search.get('node'))
  const [finding, setFinding] = useState<string | null>(null)
  const { data, loading, error, reload } = useApi<{ nodes: GraphNode[]; edges: GraphEdge[]; total_nodes: number }>(scanId ? `/api/scans/${scanId}/graph?mode=${mode}` : null)

  const filtered = useMemo(() => {
    if (!data) return null
    const keep = new Set<string>()
    const byId = new Map(data.nodes.map((n) => [n.id, n]))
    const passes = (n: GraphNode) => {
      if (n.type === 'root') return true
      if (eco && n.ecosystem !== eco) return false
      if ((n.depth ?? 99) > maxDepth) return false
      if (minSev !== 'any' && (SEV_RANK[n.max_severity || ''] ?? -1) < SEV_RANK[minSev]) return false
      if (ftype === 'vuln' && !n.vulnerability_count) return false
      if (ftype === 'signal' && !n.signal_count) return false
      return true
    }
    // keep matching nodes plus their ancestors so every visible risk stays connected to the app
    const parents = new Map<string, string[]>()
    for (const e of data.edges) { if (!parents.has(e.to)) parents.set(e.to, []); parents.get(e.to)!.push(e.from) }
    const filterActive = minSev !== 'any' || ftype !== 'all'
    for (const n of data.nodes) {
      if (!passes(n)) continue
      if (filterActive && n.type !== 'root') {
        const stack = [n.id]
        while (stack.length) { const id = stack.pop()!; if (keep.has(id)) continue; keep.add(id); for (const p of parents.get(id) || []) if (byId.get(p) && (byId.get(p)!.depth ?? 0) <= maxDepth) stack.push(p) }
      } else keep.add(n.id)
    }
    if (filterActive) for (const n of data.nodes) if (n.type === 'root' && !data.edges.some((e) => e.from === n.id && keep.has(e.to))) keep.delete(n.id)
    const nodes = data.nodes.filter((n) => keep.has(n.id))
    const edges = data.edges.filter((e) => keep.has(e.from) && keep.has(e.to))
    return { nodes, edges }
  }, [data, eco, maxDepth, minSev, ftype])

  const lay = useMemo(() => (filtered ? layout(filtered.nodes, filtered.edges) : null), [filtered])

  // highlight: all paths from roots to the selected node
  const hot = useMemo(() => {
    const nodes = new Set<string>(), edges = new Set<string>()
    if (!selected || !filtered) return { nodes, edges }
    const parents = new Map<string, string[]>()
    for (const e of filtered.edges) { if (!parents.has(e.to)) parents.set(e.to, []); parents.get(e.to)!.push(e.from) }
    const stack = [selected]
    while (stack.length) {
      const id = stack.pop()!
      if (nodes.has(id)) continue
      nodes.add(id)
      for (const p of parents.get(id) || []) { edges.add(`${p}>${id}`); stack.push(p) }
    }
    return { nodes, edges }
  }, [selected, filtered])

  // pan & zoom
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const drag = useRef<{ sx: number; sy: number; vx: number; vy: number } | null>(null)
  const boxRef = useRef<HTMLDivElement>(null)
  const fit = () => {
    if (!lay || !boxRef.current) return
    const r = boxRef.current.getBoundingClientRect()
    const k = Math.min(1.2, Math.max(0.25, Math.min(r.width / lay.width, r.height / lay.height)))
    setView({ k, x: (r.width - lay.width * k) / 2, y: Math.max(0, (r.height - lay.height * k) / 2) })
  }
  useEffect(() => { fit() }, [lay]) // eslint-disable-line react-hooks/exhaustive-deps

  if (guard) return <><PageHeader title="Dependency attack graph" />{guard}</>
  const ecos = Object.keys(result!.stats.by_ecosystem)
  return (
    <div className="fade-in">
      <PageHeader title="Dependency attack graph"
        subtitle="Every edge is backed by a parsed manifest or lockfile. Select a package to light up each path from your application to it." />
      <div className="card px-4 py-3 mb-3 flex flex-wrap items-end gap-3 text-sm">
        <label className="grid gap-1"><span className="label">View</span>
          <select className="input py-1.5" value={mode} onChange={(e) => setMode(e.target.value as 'risky' | 'full')}>
            <option value="risky">Risk paths + direct deps</option><option value="full">Full graph</option></select></label>
        <label className="grid gap-1"><span className="label">Min severity</span>
          <select className="input py-1.5" value={minSev} onChange={(e) => setMinSev(e.target.value)}>
            <option value="any">Any</option><option value="low">Low+</option><option value="medium">Medium+</option><option value="high">High+</option><option value="critical">Critical</option></select></label>
        <label className="grid gap-1"><span className="label">Finding type</span>
          <select className="input py-1.5" value={ftype} onChange={(e) => setFtype(e.target.value as 'all' | 'vuln' | 'signal')}>
            <option value="all">All packages</option><option value="vuln">With vulnerabilities</option><option value="signal">With suspicious/integrity signals</option></select></label>
        <label className="grid gap-1"><span className="label">Ecosystem</span>
          <select className="input py-1.5" value={eco} onChange={(e) => setEco(e.target.value)}><option value="">All</option>{ecos.map((x) => <option key={x}>{x}</option>)}</select></label>
        <label className="grid gap-1"><span className="label">Max depth: {maxDepth}</span>
          <input type="range" min={1} max={12} value={maxDepth} onChange={(e) => setMaxDepth(+e.target.value)} className="accent-sky-400 w-36" /></label>
        <div className="flex-1" />
        <div className="flex items-center gap-3 text-xs text-ink-400 flex-wrap">
          {(['critical', 'high', 'medium', 'low'] as const).map((s) => <span key={s} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEV_STYLE[s].hex }} />{s}</span>)}
          <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm border border-fuchsia-300" />signal only</span>
          <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm border border-dashed border-ink-400" />transitive</span>
        </div>
      </div>

      {loading && <Loading label="Building graph" />}
      {error && <ErrorState message={error} onRetry={reload} />}
      {lay && filtered && (
        <div className="grid xl:grid-cols-[1fr_380px] gap-3">
          <div ref={boxRef} className="card relative overflow-hidden h-[640px] select-none bg-[radial-gradient(circle_at_1px_1px,#1e293b_1px,transparent_0)] [background-size:22px_22px] cursor-grab active:cursor-grabbing"
            onWheel={(e) => {
              const r = e.currentTarget.getBoundingClientRect()
              const mx = e.clientX - r.left, my = e.clientY - r.top
              const k = Math.min(2.5, Math.max(0.15, view.k * (e.deltaY < 0 ? 1.12 : 0.89)))
              setView({ k, x: mx - ((mx - view.x) * k) / view.k, y: my - ((my - view.y) * k) / view.k })
            }}
            onMouseDown={(e) => { drag.current = { sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y } }}
            onMouseMove={(e) => { if (drag.current) setView({ ...view, x: drag.current.vx + e.clientX - drag.current.sx, y: drag.current.vy + e.clientY - drag.current.sy }) }}
            onMouseUp={() => { drag.current = null }} onMouseLeave={() => { drag.current = null }}>
            {filtered.nodes.length <= 1 ? (
              <div className="absolute inset-0 flex items-center justify-center text-sm text-ink-400">No packages match these filters.</div>
            ) : (
              <svg className="w-full h-full" role="img" aria-label={`Dependency graph with ${filtered.nodes.length} nodes`}>
                <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
                  {filtered.edges.map((e) => {
                    const a = lay.laid.get(e.from), b = lay.laid.get(e.to)
                    if (!a || !b) return null
                    const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2
                    const back = x2 <= x1
                    const d = back ? `M${x1},${y1} C${x1 + 60},${y1 - 60} ${x2 - 60},${y2 - 60} ${x2},${y2}` : `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`
                    const isHot = hot.edges.has(`${e.from}>${e.to}`)
                    return <path key={`${e.from}>${e.to}`} d={d} fill="none" className={isHot ? 'edge-hot' : ''}
                      stroke={isHot ? '#f43f5e' : e.relation === 'unknown-path' ? '#3b4a61' : '#2a3649'} strokeWidth={isHot ? 2.2 : 1.2}
                      strokeDasharray={!isHot && e.relation === 'unknown-path' ? '3 4' : undefined} opacity={selected && !isHot ? 0.35 : 1} />
                  })}
                  {[...lay.laid.values()].map(({ n, x, y }) => {
                    const sev = n.max_severity && n.vulnerability_count ? SEV_STYLE[n.max_severity]?.hex : null
                    const isSel = selected === n.id
                    const dim = selected && !hot.nodes.has(n.id)
                    const fill = n.type === 'root' ? '#0c2a3a' : '#131a26'
                    const stroke = n.type === 'root' ? '#38bdf8' : sev ?? (n.signal_count ? '#e879f9' : '#3b4a61')
                    return (
                      <g key={n.id} transform={`translate(${x},${y})`} opacity={dim ? 0.3 : 1} className="cursor-pointer"
                        onClick={(ev) => { ev.stopPropagation(); setSelected(n.id === selected ? null : n.id) }}
                        tabIndex={0} role="button" aria-label={`${n.name}${n.version ? '@' + n.version : ''}${n.vulnerability_count ? `, ${n.vulnerability_count} vulnerabilities` : ''}`}
                        onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); setSelected(n.id) } }}>
                        {isSel && sev && <rect x={-4} y={-4} width={NODE_W + 8} height={NODE_H + 8} rx={10} fill="none" stroke={sev} strokeWidth={2} className="node-pulse" />}
                        <rect width={NODE_W} height={NODE_H} rx={7} fill={fill} stroke={isSel ? '#e2e8f0' : stroke} strokeWidth={isSel ? 2 : sev ? 1.6 : 1}
                          strokeDasharray={n.type === 'package' && !n.direct ? '4 3' : undefined} />
                        {sev && <rect x={0} y={0} width={4} height={NODE_H} rx={2} fill={sev} />}
                        <text x={12} y={14} fontSize={11.5} fill="#e2e8f0" fontWeight={600} className="pointer-events-none">{(n.name || '').slice(0, 22)}</text>
                        <text x={12} y={27} fontSize={10} fill="#94a3b8" className="pointer-events-none mono">
                          {n.type === 'root' ? `${n.ecosystem} component` : `${n.version ?? '?'}${n.scope && n.scope !== 'runtime' ? ` · ${n.scope}` : ''}`}
                        </text>
                        {(n.vulnerability_count || 0) > 0 && (
                          <g transform={`translate(${NODE_W - 26},8)`}><rect width={20} height={17} rx={8} fill={sev!} /><text x={10} y={12.5} fontSize={10} fontWeight={700} textAnchor="middle" fill="#0b0f17">{n.vulnerability_count}</text></g>
                        )}
                        {!n.vulnerability_count && (n.signal_count || 0) > 0 && (
                          <g transform={`translate(${NODE_W - 26},8)`}><rect width={20} height={17} rx={8} fill="none" stroke="#e879f9" /><text x={10} y={12.5} fontSize={10} fontWeight={700} textAnchor="middle" fill="#e879f9">{n.signal_count}</text></g>
                        )}
                        {n.vuln_status === 'unverified' && <text x={NODE_W - 10} y={29} fontSize={9} textAnchor="end" fill="#fbbf24">?</text>}
                      </g>
                    )
                  })}
                </g>
              </svg>
            )}
            <div className="absolute right-3 top-3 flex flex-col gap-1">
              <button className="btn-ghost p-1.5 bg-ink-850" aria-label="Zoom in" onClick={() => setView({ ...view, k: Math.min(2.5, view.k * 1.2) })}><Plus size={15} /></button>
              <button className="btn-ghost p-1.5 bg-ink-850" aria-label="Zoom out" onClick={() => setView({ ...view, k: Math.max(0.15, view.k / 1.2) })}><Minus size={15} /></button>
              <button className="btn-ghost p-1.5 bg-ink-850" aria-label="Fit to screen" onClick={fit}><Maximize2 size={15} /></button>
            </div>
            <div className="absolute left-3 bottom-3 text-[11px] text-ink-400 bg-ink-900/80 rounded px-2 py-1">
              {filtered.nodes.length} of {data?.total_nodes} nodes · scroll to zoom · drag to pan · dashed border = transitive · dashed edge = path not recorded by format
            </div>
          </div>
          <SidePanel id={selected} onOpenFinding={setFinding} />
        </div>
      )}
      <Drawer open={!!finding} onClose={() => setFinding(null)} title={<span className="text-sm text-ink-300">Finding detail</span>}>
        {finding && <FindingDetail findingId={finding} />}
      </Drawer>
    </div>
  )
}

function SidePanel({ id, onOpenFinding }: { id: string | null; onOpenFinding: (id: string) => void }) {
  const { scanId } = useScan()
  const isPkg = id && !id.startsWith('root:')
  const { data, loading } = useApi<{ package: PackageInfo; findings: Finding[]; plan: Plan | null; paths: string[][] }>(
    isPkg && scanId ? `/api/scans/${scanId}/package?id=${encodeURIComponent(id!)}` : null)
  if (!id) return (
    <div className="card card-pad text-sm text-ink-400 flex flex-col items-center justify-center text-center gap-2 min-h-[200px]">
      <Crosshair className="text-accent" size={22} />
      Select a package to trace how the application reaches it, see its evidence, and the recommended fix.
    </div>
  )
  if (!isPkg) return <div className="card card-pad text-sm"><div className="label mb-1">Application component</div><div className="text-ink-100 font-semibold">{labelFor(id).name}</div><div className="text-xs text-ink-400 mono mt-1 break-all">{id}</div></div>
  if (loading || !data) return <div className="card"><Loading /></div>
  const p = data.package
  const vulns = data.findings.filter((f) => f.kind === 'vulnerability')
  const sigs = data.findings.filter((f) => f.kind !== 'vulnerability')
  return (
    <div className="card card-pad space-y-4 max-h-[640px] overflow-y-auto scrollbar-thin fade-in">
      <div>
        <div className="flex items-center gap-2 flex-wrap">{p.max_severity && <SeverityBadge s={p.max_severity} />}<span className="chip bg-ink-750 text-ink-200">{p.direct ? 'direct' : 'transitive'}</span><span className="chip bg-ink-750 text-ink-200">{p.scope}</span></div>
        <div className="text-lg font-semibold text-ink-100 mt-1.5 mono break-all">{p.name}<span className="text-ink-400">@{p.version ?? '?'}</span></div>
        <div className="text-xs text-ink-400">{p.ecosystem} · depth {p.depth ?? '?'} · {p.dependents} dependent(s) · {p.vuln_status === 'checked' ? `checked (${p.osv_origin})` : p.vuln_status === 'unverified' ? 'NOT VERIFIED' : 'not applicable'}</div>
        {p.vuln_status === 'unverified' && <div className="mt-2"><Callout tone="warn">{p.vuln_status_reason}</Callout></div>}
      </div>
      {data.paths.length > 0 && (
        <div>
          <div className="label mb-1.5">Attack paths ({data.paths.length})</div>
          <div className="space-y-1.5">{data.paths.slice(0, 5).map((path, i) => <PathView key={i} path={path} labels={labelFor} />)}</div>
        </div>
      )}
      <div>
        <div className="label mb-1.5">Vulnerabilities ({vulns.length})</div>
        {vulns.length === 0 && <div className="text-sm text-ink-400">{p.vuln_status === 'checked' ? 'None known for this exact version.' : 'Not verified.'}</div>}
        <ul className="space-y-1">
          {vulns.map((f) => (
            <li key={f.id}><button className="w-full text-left rounded-lg px-2.5 py-2 hover:bg-ink-800 flex items-start gap-2" onClick={() => onOpenFinding(f.id)}>
              <SeverityBadge s={f.severity} /><span className="text-sm text-ink-100 flex-1 leading-snug">{f.title}<span className="block mono text-[11px] text-ink-400">{f.advisory?.id}</span></span><ReachBadge level={f.reachability?.level} />
            </button></li>
          ))}
        </ul>
      </div>
      {sigs.length > 0 && (
        <div>
          <div className="label mb-1.5">Signals ({sigs.length})</div>
          <ul className="space-y-1">{sigs.map((f) => (
            <li key={f.id}><button className="w-full text-left rounded-lg px-2.5 py-2 hover:bg-ink-800 flex items-center gap-2" onClick={() => onOpenFinding(f.id)}>
              <KindBadge k={f.kind} /><span className="text-sm text-ink-100 flex-1">{f.title}</span>
            </button></li>))}</ul>
        </div>
      )}
      {data.plan && (
        <div className="rounded-lg border border-ink-700 bg-ink-900 p-3">
          <div className="label mb-1.5">Recommended fix</div>
          <div className="flex items-center gap-2 flex-wrap"><StateBadge s={data.plan.state} /><FixConfBadge c={data.plan.fix_confidence} /></div>
          <div className="mono text-sm text-ink-100 mt-1.5">{data.plan.installed} → {data.plan.target ?? 'no verified fix'}</div>
          {data.plan.actions[0] && <code className="mono text-xs text-accent block mt-1">{data.plan.actions[0].command}</code>}
        </div>
      )}
      <Link className="btn-ghost w-full justify-center" to={`/package?id=${encodeURIComponent(p.id)}`}>Open package intelligence</Link>
    </div>
  )
}
