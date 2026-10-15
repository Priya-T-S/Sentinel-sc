import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { Layout } from './components/Layout'
import { AgentsPage } from './pages/Agents'
import { FindingsPage } from './pages/Findings'
import { GraphPage } from './pages/Graph'
import { HistoryPage } from './pages/History'
import { OverviewPage } from './pages/Overview'
import { PackagePage } from './pages/Package'
import { RemediationPage } from './pages/Remediation'
import { ScanPage } from './pages/Scan'
import { SettingsPage } from './pages/Settings'
import { RouterProvider, useRouter } from './router'
import { ScanProvider } from './state'
import { EmptyState } from './components/ui'
import { Link } from './router'

function Routes() {
  const { path } = useRouter()
  let page
  if (path === '/') page = <OverviewPage />
  else if (path.startsWith('/scan')) page = <ScanPage />
  else if (path.startsWith('/graph')) page = <GraphPage />
  else if (path.startsWith('/findings')) page = <FindingsPage />
  else if (path.startsWith('/package')) page = <PackagePage />
  else if (path.startsWith('/remediation')) page = <RemediationPage />
  else if (path.startsWith('/agents')) page = <AgentsPage />
  else if (path.startsWith('/history')) page = <HistoryPage />
  else if (path.startsWith('/settings')) page = <SettingsPage />
  else page = <EmptyState title="Page not found" action={<Link className="btn-primary" to="/">Go to overview</Link>} />
  return <Layout>{page}</Layout>
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider>
      <ScanProvider>
        <Routes />
      </ScanProvider>
    </RouterProvider>
  </StrictMode>,
)
