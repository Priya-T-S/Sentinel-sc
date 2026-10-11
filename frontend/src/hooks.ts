import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api'

export interface Async<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

/** Fetch JSON for `url` (null = skip). Re-fetches when url changes. */
export function useApi<T>(url: string | null, deps: unknown[] = []): Async<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState<boolean>(!!url)
  const [tick, setTick] = useState(0)
  const reqId = useRef(0)
  useEffect(() => {
    if (!url) {
      setData(null)
      setLoading(false)
      return
    }
    const id = ++reqId.current
    setLoading(true)
    setError(null)
    api.get<T>(url)
      .then((d) => { if (id === reqId.current) setData(d) })
      .catch((e: Error) => { if (id === reqId.current) { setError(e.message); setData(null) } })
      .finally(() => { if (id === reqId.current) setLoading(false) })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, tick, ...deps])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload }
}

export function useLocalStorage<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const s = window.localStorage.getItem(key)
      return s ? (JSON.parse(s) as T) : initial
    } catch {
      return initial
    }
  })
  const set = useCallback((nv: T) => {
    setV(nv)
    try { window.localStorage.setItem(key, JSON.stringify(nv)) } catch { /* storage unavailable */ }
  }, [key])
  return [v, set]
}

export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}
