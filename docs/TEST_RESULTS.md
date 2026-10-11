# Test results

Recorded 2026-10-12 on Windows 11, Python 3.12.3, Node 24.21.0, Microsoft Edge (headless) via playwright-core 1.63.0.
All runs below are from a clean data directory.

## Final run

| Suite | Command | Result |
|---|---|---|
| Backend unit, functional, security, API | `cd backend && python -m pytest tests -q` | **126 passed, 1 skipped** (symlink test skipped: creating symlinks on Windows needs admin rights; the control is still active) |
| Frontend type-check + build | `cd frontend && npm run build` | **pass** (290 KB JS / 85 KB gzip) |
| End-to-end judging flow, live intelligence | `npm run e2e` (server on :8000) | **20/20 checks passed** |
| End-to-end judging flow, offline/fixture | `npm run e2e:offline` | **20/20 checks passed** |
| Detector's Python dependencies | `pip-audit -r backend/requirements.txt` | **No known vulnerabilities found** |
| Detector's npm dependencies | `npm audit` | **found 0 vulnerabilities** |
| CLI gate on demo (live) | `python -m sentinel scan ../demo/demo-app` | FAIL verdict, exit **1** (expected: 2 critical vulns + pwn-request workflow) |
| CLI gate on a clean project | lockfile with `dayjs@1.11.13` | PASS, exit **0** |
| CLI gate with no intelligence | `--offline` with an empty cache | FAIL (`fail_on_intelligence_unavailable`), exit **1** — never a false clean |
| CLI missing target | `scan /nonexistent` | exit **2** |
| Own CI workflow self-scan | `scan_workflows` on this repo | no findings |
| Server log during E2E | grep traceback/error | 0 matches |

E2E checks: demo loads → real stages shown → overview shows verified vulnerabilities → selecting `qs` highlights
4 path edges → advisory affected range and applicability → `_.template` call site → "Why this score?" →
fix shown → patch preview → SIMULATED what-if → patch download → JSON/HTML/CycloneDX/gate exports →
typosquat package intel → policy evaluation → keyboard-selectable graph nodes → no horizontal scroll at 390 px →
no browser console errors.

Test inventory: `test_versions.py` (version ordering per ecosystem, npm ranges, OSV range semantics, CVSS reference
vectors), `test_parsers.py` (every supported format, nested npm resolution, drift, malformed and unsupported
inputs), `test_engine_demo.py` (expected findings, clean control, paths, alias merge, reachability, score bounds,
heuristics labelling, verified remediation, what-if, deterministic policy, SBOM export/round-trip, no false clean),
`test_security.py` (archive traversal/symlink/bomb, XXE, YAML tags, deep JSON, injection payloads, no subprocess,
SSRF/egress allow-list, redirect revalidation, oversized/malformed responses, XSS escaping, secret redaction,
workflow risks), `test_api.py` (full flow, upload, dedupe, compare, policy, CSRF, Host/DNS-rebinding, headers,
CORS, upload rejections, size limit, ID injection, SQL injection, SPA traversal, what-if validation, rate limit,
security events).

## Defects found during development (and fixed)

| Found by | Defect | Fix |
|---|---|---|
| Manual inspection of first live scan | `requests` got a false "call-site" level: the advisory text mentions "requests" and the import line matched | package/module names are excluded from advisory symbols; Python sub-path matching only for dotted imports |
| Manual inspection | Transitive fixes checked whether a parent's range admitted *exactly* the target (cookie wrongly reported "no express release admits it") | path resolution through registry ranges (highest satisfying version per hop, across all paths through the direct dependency) |
| Manual inspection | Combined patch kept the *last* express version (4.21.1) instead of the highest required (4.22.3) | per-package maximum across plans |
| Manual inspection | `safer-buffer` flagged as typosquat of `safe-buffer` at medium | name similarity escalates only with corroborating evidence; established packages → info |
| Manual inspection | Aliased advisories with different fixed versions (lodash 4.17.21 vs 4.18.0) could under-fix | group fix = max of each member's first fixed version |
| Offline experiment | Gate only *warned* when intelligence was unavailable → possible false clean in CI | split `intel_unavailable` (fails by default) from `no_exact_version` (warns) |
| `test_security.py` | `safe_name("../../x")` accepted | `.`/`..` segments rejected |
| `test_security.py` | archive normaliser stripped a lone `.github/` top folder, hiding workflows | dot-directories never stripped |
| E2E (390 px) | Overview overflowed 833 px horizontally; Settings tabs overflowed | `min-w-0` on cards, scrollable tab bar |
| Workflow SHA verification against GitHub | upload-artifact SHA had a one-character typo | corrected to the verified SHA |
| npm audit / pip-audit | initial pins (vite 5.4.11, react-router 6.28, tailwind 3, starlette 0.41, python-multipart 0.0.20) had advisories | upgraded to patched releases ≥2 weeks old; react-router removed |

## Not tested / known gaps
- Screen-reader testing was not performed (keyboard selection, landmarks, skip link and ARIA labels are present).
- No load testing beyond the configured limits; no fuzzing campaign (adversarial inputs are hand-written cases).
- The symlink test does not run on Windows without admin rights.
- Passing tests do not constitute a security audit.
