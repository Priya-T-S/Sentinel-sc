# Supported ecosystems and limitations

Lockfiles are preferred because they record **exact** versions. A dependency without an exact version is never
matched by guessing; it is reported as **Not verified**. Recognised-but-unsupported files are reported, never
silently treated as clean.

| Ecosystem | File | Support | Exact versions | Transitive edges | Integrity | Notes |
|---|---|---|---|---|---|---|
| npm | `package-lock.json` / `npm-shrinkwrap.json` v1–v3 | **Full** | ✔ | ✔ incl. nested copies, links | ✔ | dev/optional/peer, `hasInstallScript` |
| npm | `yarn.lock` v1 and berry | **Full** | ✔ | ✔ | ✔ | dev/runtime inferred from package.json |
| npm | `pnpm-lock.yaml` v5/v6/v9 | Partial | ✔ | ✔ | ✔ | only the root importer is a component |
| npm | `package.json` without lockfile | Partial | exact pins only | direct only | — | ranges unverified; "missing lockfile" finding |
| npm | `.npmrc` | Config | — | — | — | scoped registries, literal tokens |
| PyPI | `poetry.lock` + `pyproject.toml` | **Full** | ✔ | ✔ | ✔ | |
| PyPI | `Pipfile.lock` | Partial | ✔ | ✘ (format has none) | ✔ | direct from `Pipfile` if present |
| PyPI | `requirements*.txt`, `constraints*.txt` | Partial | `==` pins | pip-compile `# via` only | `--hash` | `-r`/`-c` (bounded, cannot escape repo), index URLs, VCS refs |
| PyPI | `pyproject.toml` without lock | Partial | exact pins only | direct only | — | |
| PyPI | `setup.py`, `setup.cfg` | Unsupported | | | | setup.py is code and is never run |
| Go | `go.mod` + `go.sum` | Partial | ✔ | direct ✔, indirect parents unknown | ✔ `h1:` | `replace` noted |
| Go | `go.work`, `vendor/modules.txt` | Unsupported | | | | |
| crates.io | `Cargo.lock` + `Cargo.toml` | **Full** | ✔ | ✔ | ✔ | workspace crates are components |
| crates.io | `Cargo.toml` without lock | Partial | `=` pins | direct only | — | |
| Maven | `pom.xml` | Partial | literal / `${prop}` | direct only | — | parent POMs/BOMs not fetched |
| Maven | `gradle.lockfile` | Partial | ✔ | ✘ | — | |
| Maven | `build.gradle(.kts)` | Partial | literal coordinates | direct only | — | pattern-based, never executed |
| NuGet | `packages.lock.json` | **Full** | ✔ | ✔ | ✔ | frameworks merged |
| NuGet | `*.csproj`, `packages.config` | Partial | literal | direct only | — | |
| SBOM | CycloneDX JSON 1.2–1.6 | **Full** | ✔ (purl) | ✔ | ✔ | no source → reachability "unknown" |
| SBOM | CycloneDX XML, SPDX | Unsupported | | | | |
| other | `Gemfile.lock`, `composer.lock` | Unsupported | | | | |

## Input sources

| Source | How | Notes |
|---|---|---|
| Upload | `.zip` of a repository, a single lockfile/manifest, or a CycloneDX JSON SBOM | read in memory |
| Local directory | CLI: `python -m sentinel scan ./path` | symlinks never followed |
| **Public GitHub repository** | Scan page URL box, or CLI `scan https://github.com/owner/repo[/tree/<ref>]` | resolved to an exact commit; public repos only; online only |
| **Two versions (PR review)** | CLI `review --base … --head …`, History page, PR workflow | any of the inputs above on each side |

## Build provenance verification

| Ecosystem | Verified | Notes |
|---|---|---|
| npm | ✔ SLSA v1 provenance built on GitHub Actions (Sigstore signature, Fulcio identity, Rekor proof, SHA-512 bound to lockfile) | other CI providers → "unsupported"; npm publish attestation not checked; ≤60 per scan |
| PyPI, Go, crates.io, Maven, NuGet | ✘ | reported as unknown |

## Intelligence
| Provider | Ecosystems | Used for |
|---|---|---|
| OSV.dev | npm, PyPI, Go, crates.io, Maven, NuGet | matching, details, fixed versions, candidate re-checks |
| npm registry | npm | dates, versions, maintainers, install scripts, deprecation, provenance attestations (verified with Sigstore), dependency ranges |
| PyPI JSON API | PyPI | release dates, yanks, project URLs |
| OpenSSF Scorecard | GitHub-hosted direct deps | repository posture |
| CISA KEV / FIRST EPSS | any with CVE aliases | known exploitation / probability |

## Reachability
| Language | Imports | Call sites |
|---|---|---|
| JS/TS (`.js .mjs .cjs .jsx .ts .tsx .vue .svelte`) | `import`, `require`, dynamic `import()`, sub-paths | `binding.symbol(`, named/destructured imports, `pkg/symbol` |
| Python | `import x`, `from x import y` (dist→module map) | `module.symbol(`, imported names |
| Go | module-prefix import paths | `alias.Symbol(` with OSV symbols |

## Version semantics
- npm/crates/Go: SemVer 2.0 precedence; node-semver ranges (`^ ~ x * - ||`), 0.x caret rules, prerelease exclusion; Go `v` prefix.
- PyPI: PEP 440 via `packaging`. Maven: qualifier ordering and `[a,b)` ranges. NuGet: 4-part + prerelease.
- OSV `SEMVER`/`ECOSYSTEM` ranges evaluated locally (`introduced`/`fixed`/`last_affected`/`limit`, explicit versions);
  `GIT`-only ranges are "could not be evaluated", never "safe".
