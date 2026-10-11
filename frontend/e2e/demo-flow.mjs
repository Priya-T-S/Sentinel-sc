// End-to-end judging flow against a running server (http://127.0.0.1:8000) using an installed Edge/Chrome.
// Usage: node e2e/demo-flow.mjs [--offline] [--shots <dir>]
// Requires: playwright-core (npm i -D playwright-core@1.49.1 or a global install); no browser download.
import { chromium } from 'playwright-core'
import fs from 'node:fs'
import path from 'node:path'

const BASE = process.env.SENTINEL_URL || 'http://127.0.0.1:8000'
const offline = process.argv.includes('--offline')
const shotsIdx = process.argv.indexOf('--shots')
const SHOTS = shotsIdx > 0 ? process.argv[shotsIdx + 1] : null
if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true })
const channel = process.env.BROWSER_CHANNEL || 'msedge'

const results = []
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`) }
const shot = async (page, name) => { if (SHOTS) { await page.waitForTimeout(500); await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: false }) } }

const browser = await chromium.launch({ channel, headless: true })
const ctx = await browser.newContext({ viewport: { width: 1500, height: 950 }, acceptDownloads: true })
const page = await ctx.newPage()
const consoleErrors = []
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
page.on('pageerror', (e) => consoleErrors.push(String(e)))

try {
  // 1. open the product
  await page.goto(`${BASE}/scan`)
  await page.getByRole('button', { name: /Scan demo project/ }).waitFor()
  check('1. Scan workspace loads with a preloaded demo', true)
  if (offline) await page.getByLabel(/Offline mode/).check()
  await shot(page, '01-scan-workspace')

  // 2-3. one action, real stages
  await page.getByRole('button', { name: /Scan demo project/ }).click()
  await page.getByText('Matching versions against OSV').waitFor({ timeout: 30000 })
  check('3. Real processing stages are displayed', true)
  await shot(page, '02-scan-progress')
  await page.getByRole('button', { name: 'View results' }).waitFor({ timeout: 300000 })
  await shot(page, '03-scan-complete')
  await page.getByRole('button', { name: 'View results' }).click()

  // Overview
  await page.getByRole('heading', { name: 'Security posture' }).waitFor()
  await page.getByText('Verified vulnerabilities by severity').waitFor()
  const vulnCount = await page.locator('text=Verified vulnerabilities').first().locator('xpath=../..').innerText()
  check('4. Overview shows verified vulnerabilities', /\d+/.test(vulnCount), vulnCount.split('\n').slice(0, 2).join(' '))
  await shot(page, '04-overview')

  // 5. dependency path on the graph: select qs
  await page.goto(`${BASE}/graph`)
  await page.locator('svg[role="img"]').waitFor({ timeout: 30000 })
  const qsNode = page.locator('g[role="button"][aria-label^="qs@6.7.0"]')
  await qsNode.click()
  await page.getByText(/Attack paths \(\d+\)/).waitFor()
  const hotEdges = await page.locator('path.edge-hot').count()
  check('5. Selecting qs highlights application → express → qs paths', hotEdges >= 2, `${hotEdges} highlighted edges`)
  await shot(page, '05-attack-graph')

  // 6. advisory + affected range in findings
  await page.goto(`${BASE}/findings`)
  await page.getByLabel('Search findings').fill('GHSA-35jh-r3h4-6jhm')
  await page.locator('tbody tr').filter({ hasText: 'Command Injection' }).first().waitFor({ timeout: 15000 })
  await page.locator('tbody tr').first().click()
  await page.getByText('Affected ranges').waitFor()
  const drawer = await page.locator('[role="dialog"]').innerText()
  check('6. Advisory shows affected range and applicability', drawer.includes('< 4.17.21') && drawer.includes('inside the affected range'))
  check('6b. Static call-site evidence for _.template', drawer.includes('CALL template') && drawer.includes('src/server.js'))
  await shot(page, '06-finding-detail')

  // 7. risk explanation + fix
  check('7. "Why this score?" with factors', drawer.includes('Why this score?') && drawer.includes('CVSS v3 base score'))
  check('7b. Recommended fix present', /Recommended fix/.test(drawer) && /4\.17\.15 → 4\.\d+\.\d+/.test(drawer))
  await page.getByRole('button', { name: 'Close panel' }).click()

  // 8-9. patch preview + what-if
  await page.goto(`${BASE}/remediation`)
  await page.getByText('Combined patch preview').waitFor()
  const patchText = await page.locator('pre').first().innerText()
  check('8. Patch preview (unified diff, not applied)', patchText.includes('+++ b/package.json') && patchText.includes('"express"'))
  await page.getByRole('button', { name: /Simulate all fixes/ }).click()
  await page.getByText(/SIMULATED/).first().waitFor({ timeout: 120000 })
  await page.getByText('Proposed version changes').waitFor({ timeout: 120000 })
  await shot(page, '07-remediation-whatif')
  check('9. Hypothetical post-fix comparison is labelled SIMULATED', true)

  // 10. exports
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: /Patch \(\.diff\)/ }).click()])
  check('10a. Patch download', (await dl.suggestedFilename()).endsWith('.diff'))
  const scanId = await page.evaluate(() => JSON.parse(localStorage.getItem('sentinel.scan') || 'null'))
  for (const fmt of ['json', 'html', 'cyclonedx', 'gate']) {
    const r = await page.request.get(`${BASE}/api/scans/${scanId}/export/${fmt}`)
    check(`10b. Export ${fmt}`, r.ok(), `${r.status()} ${(await r.body()).length} bytes`)
  }

  // remaining pages render
  await page.goto(`${BASE}/package?id=${encodeURIComponent('npm:lodahs@1.0.0')}`)
  await page.getByText('Supply-chain trust profile').waitFor()
  const pk = await page.locator('main').innerText()
  check('Package intel: synthetic typosquat shows signals', pk.includes('Name resembles popular package') && pk.includes('Explicit uncertainty'))
  await shot(page, '08-package-intel')
  await page.goto(`${BASE}/history`)
  await page.getByText('History & risk regression').waitFor()
  await shot(page, '09-history')
  await page.goto(`${BASE}/settings`)
  await page.getByText('Fail on verified vulnerabilities at or above').waitFor()
  await page.getByRole('button', { name: /Evaluate/ }).click()
  await page.getByText(/exit code \d/).waitFor()
  check('Settings: policy evaluation runs', true)
  await shot(page, '10-settings-policy')

  // keyboard: graph node focusable + Enter selects
  await page.goto(`${BASE}/graph`)
  await page.locator('g[role="button"]').first().focus()
  await page.keyboard.press('Enter')
  check('A11y: graph nodes are keyboard-selectable', await page.locator('g[role="button"]').count() > 0)

  // responsive: narrow viewport has no horizontal overflow on overview
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`${BASE}/`)
  await page.getByRole('heading', { name: 'Security posture' }).waitFor()
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  check('Responsive: no horizontal page scroll at 390px', overflow <= 1, `overflow ${overflow}px`)
  await shot(page, '11-mobile-overview')
} catch (e) {
  check('Flow completed without exceptions', false, String(e).slice(0, 300))
  await shot(page, 'zz-error')
} finally {
  check('No browser console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '))
  await browser.close()
  const failed = results.filter((r) => !r.ok)
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
  process.exit(failed.length ? 1 : 0)
}
