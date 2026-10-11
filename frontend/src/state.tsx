import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from './api'
import { useLocalStorage } from './hooks'
import type { ScanResult, ScanRow } from './types'

interface ScanCtx {
  scanId: string | null
  setScanId: (id: string | null) => void
  result: ScanResult | null
  loading: boolean
  error: string | null
  scans: ScanRow[]
  refreshScans: () => Promise<void>
  reloadResult: () => void
}

const Ctx = createContext<ScanCtx | null>(null)

export function ScanProvider({ children }: { children: ReactNode }) {
  const [scanId, setScanIdRaw] = useLocalStorage<string | null>('sentinel.scan', null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scans, setScans] = useState<ScanRow[]>([])
  const [tick, setTick] = useState(0)

  const refreshScans = useCallback(async () => {
    try {
      const r = await api.get<{ items: ScanRow[] }>('/api/scans?limit=100')
      setScans(r.items)
      return
    } catch {
      setScans([])
    }
  }, [])

  useEffect(() => { refreshScans() }, [refreshScans])

  // auto-select most recent completed scan when nothing (valid) is selected
  useEffect(() => {
    if (!scans.length) return
    const valid = scanId && scans.some((s) => s.id === scanId && s.status === 'completed')
    if (!valid) {
      const latest = scans.find((s) => s.status === 'completed')
      if (latest && latest.id !== scanId) setScanIdRaw(latest.id)
    }
  }, [scans, scanId, setScanIdRaw])

  useEffect(() => {
    if (!scanId) { setResult(null); return }
    let cancelled = false
    setLoading(true)
    setError(null)
    api.get<ScanResult>(`/api/scans/${scanId}/result`)
      .then((r) => { if (!cancelled) { setRootNames(r.roots); setResult(r) } })
      .catch((e: Error) => { if (!cancelled) { setResult(null); setError(e.message) } })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [scanId, tick])

  const setScanId = useCallback((id: string | null) => setScanIdRaw(id), [setScanIdRaw])
  const reloadResult = useCallback(() => setTick((t) => t + 1), [])
  const value = useMemo(() => ({ scanId, setScanId, result, loading, error, scans, refreshScans, reloadResult }),
    [scanId, setScanId, result, loading, error, scans, refreshScans, reloadResult])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useScan() {
  const v = useContext(Ctx)
  if (!v) throw new Error('ScanProvider missing')
  return v
}

const rootNames = new Map<string, string>()
export function setRootNames(roots: { id: string; name: string }[] | undefined) {
  rootNames.clear()
  for (const r of roots || []) rootNames.set(r.id, r.name)
}

/** Map package/root ids to display labels. */
export function labelFor(id: string): { name: string; version?: string | null; root?: boolean } {
  if (rootNames.has(id)) return { name: rootNames.get(id)!, root: true }
  if (id.startsWith('root:')) {
    const parts = id.split(':')
    const dir = parts[2] === '.' ? '' : parts[2]
    const sub = parts.slice(3).join(':')
    return { name: sub ? `${dir ? dir + '/' : ''}${sub}` : (dir || 'application'), root: true }
  }
  const m = id.match(/^[^:]+:(.+)@([^@]*)$/)
  if (!m) return { name: id }
  return { name: m[1], version: m[2] === '?' ? null : m[2] }
}
