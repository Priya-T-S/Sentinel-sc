# Demo script (≈5 minutes)

**Setup (before judges arrive):** `./scripts/start.ps1` (or `start.sh`), open http://127.0.0.1:8000.
For a clean slate: Settings → Privacy & retention → **Reset demo dataset**. No network? Tick **Offline mode** on the
Scan page — results come from the versioned snapshot and are labelled `fixture`.

| # | Do | Say / point at |
|---|---|---|
| 1 | **Scan workspace** | "A realistic Express + Python service. Real packages, real vulnerable pins, one clearly-labelled synthetic typosquat." Point at *What leaves your machine*. |
| 2 | Click **Scan demo project** | Watch the 12 real stages: OSV matching, advisory retrieval, registry/provenance, reachability, fix verification. |
| 3 | **View results** (Overview) | 50 verified vulnerabilities vs 10 suspicious signals kept separate; *Not verified: 1* (`flask>=2.0`, no exact version — we never call it clean). Gate = FAIL with 3 reasons. Provider freshness table. |
| 4 | **Attack graph** → click `qs` | Two highlighted paths: app → express → qs and app → express → body-parser → qs. Side panel: 4 advisories, "Reached via imported dependency". |
| 5 | **Findings** → search `CVE-2021-23337` → open | Affected range `< 4.17.21` and *"4.17.15 is inside the range (local check agrees with OSV)"*; GHSA-r5fr merged as alias (counted once). Reachability: **CALL template at src/server.js:16**. |
| 6 | Scroll to **Why this score?** | CVSS 7.2 from the vector, ×1.0 call-site, ×1.0 runtime, +10 verified fix, +EPSS 21%. Then the evidence ledger with sources and retrieval times. |
| 7 | Contrast: filter severity = critical | `minimist` is critical but dev-only and never imported → P4. "Severity is not priority." |
| 8 | **Remediation** | One patch: express 4.17.1 → 4.22.3 fixes six transitive packages through express's own declared ranges (each hop shown), every target re-checked on OSV ("Fix verified"). axios is "Requires review" (0.x boundary). |
| 9 | **Simulate all fixes** | 50 → 0 known advisories — clearly labelled SIMULATED with its limitations. |
| 10 | Download **Patch (.diff)**, **Remediation report**, then Findings → **SBOM + VEX** | Exports: JSON, HTML, CycloneDX 1.5 with VEX `in_triage`, gate JSON. |
| 11 | **Package intel** → `lodahs` | Typosquat of lodash corroborated by direct use + postinstall + local source; source inspection shows `eval`, base64 decoded statically to `console.log("demo")`, env exfil pattern. "Signal for review, not a malware verdict." |
| 12 | (optional) Terminal | `cd backend && python -m sentinel scan ../demo/demo-app --offline` → exit code 1, CI-ready. |

**If the network drops:** rerun with Offline mode; every fact is labelled `fixture` with its 2026-10-12 retrieval time.
