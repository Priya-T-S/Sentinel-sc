import { Radar } from 'lucide-react'
import { Link } from '../router'
import { useScan } from '../state'
import { EmptyState, ErrorState, Loading } from './ui'

/** Shared guard for pages that need a completed scan. Returns a node to render, or null when ready. */
export function useScanGuard() {
  const { result, loading, error, scanId, reloadResult } = useScan()
  if (loading && !result) return <Loading label="Loading scan" />
  if (error) return <ErrorState message={error} onRetry={reloadResult} />
  if (!scanId || !result) {
    return (
      <div className="card">
        <EmptyState
          icon={<Radar size={22} />}
          title="No scan yet"
          body="Run the preloaded demo project or upload a repository archive, lockfile or CycloneDX SBOM to see dependency risk here."
          action={<Link to="/scan" className="btn-primary">Open scan workspace</Link>}
        />
      </div>
    )
  }
  return null
}
