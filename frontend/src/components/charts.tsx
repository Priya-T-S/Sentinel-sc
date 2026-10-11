// Small, dependency-free SVG/HTML charts. Severity colours always ship with text labels (never colour alone).
import { useState } from 'react'
import { SEV_STYLE } from './ui'

/** Horizontal stacked bar (part-to-whole) with 2px gaps, legend and per-segment hover. */
export function SeverityBar({ counts, onPick }: { counts: Record<string, number>; onPick?: (sev: string) => void }) {
  const order = ['critical', 'high', 'medium', 'low', 'unknown']
  const total = order.reduce((a, k) => a + (counts[k] || 0), 0)
  const [hover, setHover] = useState<string | null>(null)
  if (!total) return <div className="text-sm text-ink-400">No verified vulnerabilities.</div>
  return (
    <div>
      <div className="flex h-3 w-full gap-[2px]" role="img" aria-label={order.map((k) => `${k}: ${counts[k] || 0}`).join(', ')}>
        {order.filter((k) => counts[k]).map((k) => (
          <button key={k} type="button" onMouseEnter={() => setHover(k)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(k)} onBlur={() => setHover(null)}
            onClick={() => onPick?.(k)} className="h-full first:rounded-l last:rounded-r transition-opacity"
            style={{ width: `${(100 * counts[k]) / total}%`, background: SEV_STYLE[k].hex, opacity: hover && hover !== k ? 0.45 : 1 }}
            aria-label={`${counts[k]} ${k}`} />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs">
        {order.map((k) => (
          <button key={k} type="button" className={`flex items-center gap-1.5 ${hover === k ? 'text-ink-100' : 'text-ink-300'}`} onClick={() => onPick?.(k)}
            onMouseEnter={() => setHover(k)} onMouseLeave={() => setHover(null)}>
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEV_STYLE[k].hex }} />
            <span className="capitalize">{k}</span><span className="tabular-nums font-semibold text-ink-100">{counts[k] || 0}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

/** Horizontal bars for magnitude comparison, one hue, direct labels. */
export function HBars({ rows, max }: { rows: { label: string; value: number; sub?: string }[]; max?: number }) {
  const m = max ?? Math.max(1, ...rows.map((r) => r.value))
  return (
    <div className="space-y-2.5">
      {rows.map((r) => (
        <div key={r.label} className="grid grid-cols-[8rem_1fr_auto] items-center gap-3 text-sm" title={`${r.label}: ${r.value}${r.sub ? ` (${r.sub})` : ''}`}>
          <span className="text-ink-300 truncate">{r.label}</span>
          <div className="h-2 rounded-full bg-ink-750"><div className="h-2 rounded-r-full rounded-l-sm bg-accent" style={{ width: `${(100 * r.value) / m}%` }} /></div>
          <span className="tabular-nums text-ink-100 text-xs w-24 text-right">{r.value}{r.sub && <span className="text-ink-400"> · {r.sub}</span>}</span>
        </div>
      ))}
    </div>
  )
}

/** Single-series line over time with crosshair tooltip. */
export function TrendLine({ points, label }: { points: { t: number; v: number; note?: string }[]; label: string }) {
  const [hi, setHi] = useState<number | null>(null)
  if (points.length < 2) return <div className="text-sm text-ink-400 py-6">Run at least two scans to see a trend.</div>
  const W = 560, H = 140, P = { l: 32, r: 12, t: 12, b: 22 }
  const max = Math.max(1, ...points.map((p) => p.v))
  const x = (i: number) => P.l + (i * (W - P.l - P.r)) / (points.length - 1)
  const y = (v: number) => P.t + (H - P.t - P.b) * (1 - v / max)
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p.v)}`).join(' ')
  const ticks = [0, Math.round(max / 2), max]
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label={`${label} over ${points.length} scans`}
        onMouseLeave={() => setHi(null)}
        onMouseMove={(e) => {
          const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect()
          const px = ((e.clientX - r.left) / r.width) * W
          let best = 0
          points.forEach((_, i) => { if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i })
          setHi(best)
        }}>
        {ticks.map((t) => (
          <g key={t}><line x1={P.l} x2={W - P.r} y1={y(t)} y2={y(t)} stroke="#1e293b" strokeWidth={1} />
            <text x={P.l - 6} y={y(t) + 3} textAnchor="end" fontSize="10" fill="#64748b">{t}</text></g>
        ))}
        <path d={d} fill="none" stroke="#38bdf8" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {points.map((p, i) => <circle key={i} cx={x(i)} cy={y(p.v)} r={hi === i ? 5 : 3.5} fill="#38bdf8" stroke="#0f141e" strokeWidth={2} />)}
        {hi != null && <line x1={x(hi)} x2={x(hi)} y1={P.t} y2={H - P.b} stroke="#94a3b8" strokeDasharray="3 3" strokeWidth={1} />}
        <text x={P.l} y={H - 4} fontSize="10" fill="#64748b">{new Date(points[0].t * 1000).toLocaleDateString()}</text>
        <text x={W - P.r} y={H - 4} fontSize="10" fill="#64748b" textAnchor="end">{new Date(points[points.length - 1].t * 1000).toLocaleDateString()}</text>
      </svg>
      {hi != null && (
        <div className="absolute top-0 pointer-events-none rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs shadow-lg"
          style={{ left: `${(x(hi) / W) * 100}%`, transform: 'translateX(-50%)' }}>
          <div className="text-ink-100 font-semibold tabular-nums">{points[hi].v} {label}</div>
          <div className="text-ink-400">{new Date(points[hi].t * 1000).toLocaleString()}</div>
          {points[hi].note && <div className="text-ink-300">{points[hi].note}</div>}
        </div>
      )}
    </div>
  )
}
