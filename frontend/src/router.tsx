// Tiny History-API router (avoids a third-party router dependency for a handful of internal routes).
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type AnchorHTMLAttributes, type ReactNode } from 'react'

interface RouterState {
  path: string
  search: URLSearchParams
  navigate: (to: string, opts?: { replace?: boolean }) => void
}

const Ctx = createContext<RouterState | null>(null)

function current() {
  return { path: window.location.pathname || '/', search: new URLSearchParams(window.location.search) }
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [loc, setLoc] = useState(current)
  useEffect(() => {
    const on = () => setLoc(current())
    window.addEventListener('popstate', on)
    return () => window.removeEventListener('popstate', on)
  }, [])
  const navigate = useCallback((to: string, opts?: { replace?: boolean }) => {
    // internal paths only
    if (!to.startsWith('/') || to.startsWith('//')) return
    if (opts?.replace) window.history.replaceState(null, '', to)
    else window.history.pushState(null, '', to)
    setLoc(current())
    window.scrollTo({ top: 0 })
  }, [])
  const value = useMemo(() => ({ ...loc, navigate }), [loc, navigate])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useRouter() {
  const v = useContext(Ctx)
  if (!v) throw new Error('RouterProvider missing')
  return v
}

export function Link({ to, children, ...rest }: { to: string } & AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { navigate } = useRouter()
  return (
    <a
      href={to}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
        e.preventDefault()
        navigate(to)
      }}
      {...rest}
    >
      {children}
    </a>
  )
}
