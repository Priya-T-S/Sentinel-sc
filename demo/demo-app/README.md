# acme-orders-api (SENTINEL-SC demo target)

**Intentionally vulnerable. Never install, deploy, or run `npm install` here.**

This folder is a realistic dependency fixture used to demonstrate SENTINEL-SC:

| Scenario | Where | Real or synthetic |
|---|---|---|
| Direct vulnerable dependency | `lodash@4.17.15`, `axios@0.21.1`, `minimist@1.2.5` (dev) | Real packages, real OSV advisories |
| Transitive vulnerable dependency | `express@4.17.1` → `body-parser` → `qs@6.7.0`, `path-to-regexp@0.1.7`, `cookie@0.4.0`, `send`, `serve-static` | Real |
| Static call-site evidence | `src/server.js` calls `_.template`, `src/routes/orders.js` calls `merge` | Real code paths |
| Non-vulnerable control | `dayjs` (resolved to a current release) | Real |
| Second ecosystem | `services/report-worker/requirements.txt` (PyYAML 5.3.1, requests 2.25.1) | Real |
| Typosquat + install script + obfuscation | `lodahs` → `vendor/lodahs` | **SYNTHETIC, clearly labelled, inert** |
| CI/CD risks | `.github/workflows/ci.yml` (`pull_request_target` + PR head checkout, `write-all`, unpinned action, script injection) | Synthetic config |
| Secret exposure | `config/default.json` uses AWS's documented example key `AKIAIOSFODNN7EXAMPLE` | Documented example value |

`package-lock.json` was generated with `npm install --package-lock-only --ignore-scripts`
(resolution only — nothing was installed or executed).
