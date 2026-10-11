# Threat model

SENTINEL-SC processes **untrusted input by design**: repositories, archives, manifests, package source,
registry metadata and advisory text may all be hostile. A false "clean" verdict is itself a security failure.

## Trust boundaries
1. Browser ↔ local API — any website the operator visits can attempt cross-site requests or DNS rebinding to 127.0.0.1.
2. Scanned repository ↔ engine — attacker-controlled bytes, names and structure.
3. Engine ↔ public providers — responses may be slow, oversized, malformed or redirected.
4. Engine output ↔ consumers — UI, HTML report, JSON, SBOM and CI logs render attacker-influenced text.

## Repository and parser attacks
| Threat | Control | Test(s) |
|---|---|---|
| Path traversal / absolute paths in archives | Archives never extracted; names normalised; `..`, absolute, drive paths rejected and reported | `test_traversal_names_rejected`, `test_zip_traversal_and_absolute_entries_never_exposed`, `test_upload_traversal_zip_rejected_entries_reported` |
| Symlink escape | Zip symlink entries rejected; directory scans never follow links and re-check real paths | `test_zip_symlink_entries_rejected`, `test_dirsource_*` |
| Zip/decompression bombs | Entry count, declared size, ratio, per-file and total caps; reads capped at limit+1 regardless of headers | `test_zip_bomb_ratio_rejected`, `test_zip_lying_header_is_capped`, `test_invalid_and_oversized_archives` |
| Malformed manifests / parser crashes | Every parser wrapped; errors become a per-file `error` outcome | `test_malformed_inputs_reported_not_crashing`, `test_deeply_nested_json_does_not_crash` |
| XXE / billion laughs | `defusedxml`, DTDs forbidden | `test_xxe_and_billion_laughs_blocked` |
| YAML object construction | `yaml.safe_load` only | `test_yaml_object_tags_not_constructed` |
| Oversized graphs | 20 000-package cap; bounded path enumeration | — |
| Command injection via names/versions/paths | No shell or subprocess anywhere in the engine (asserted); strict name charset, `..` segments rejected | `test_command_injection_style_names_rejected`, `test_injection_payloads_in_manifests_are_inert`, `test_engine_never_spawns_processes` |
| Executing scanned code | Nothing installed, imported or executed; source read as text; base64 decoded for display only | demo `lodahs` |
| Unsupported input passing as clean | Unsupported files reported; no exact version / no intelligence → *Not verified* | `test_unsupported_files_are_reported_not_silently_clean`, `test_no_false_clean_when_intelligence_unavailable` |

## Network attacks
| Threat | Control | Test(s) |
|---|---|---|
| SSRF | No user-supplied URLs are fetched; fixed allow-list of 6 public HTTPS hosts | `test_egress_blocked` (loopback, RFC1918, metadata IP, IPv6, look-alikes, credentials, ports, schemes) |
| Redirect to internal address | Auto-redirects off; each hop re-validated (max 3) | `test_redirect_to_internal_host_blocked` |
| DNS rebinding of provider names | Allow-listed names over TLS with verification; a rebinding attacker cannot present valid certificates | — |
| Oversized/malformed/slow responses | Streaming size caps, parse errors handled, timeouts, bounded retries with backoff | `test_oversized_and_malformed_provider_responses` |
| Outage hiding vulnerabilities | Stale/fixture fallback is labelled; no data → *Not verified* and the gate fails | `test_no_false_clean_when_intelligence_unavailable` |
| Request floods | 600 API req/min and 20 scan creations/min per client; ≤2 running/≤6 queued scans; timeout | `test_rate_limit_scan_creation` |

## Application attacks
| Threat | Control | Test(s) |
|---|---|---|
| XSS via package names/advisory text | React text escaping; only http(s) links rendered; HTML report escapes everything and has its own `default-src 'none'` CSP; app CSP `script-src 'self'` | `test_html_report_escapes_untrusted_text` |
| CSRF / drive-by requests | State changes require `X-Sentinel-Client`; no CORS granted, so cross-origin pages cannot send it; no cookies | `test_csrf_header_required`, `test_no_cors_preflight_approval` |
| DNS rebinding against the local API | Host header allow-list → 421 | `test_dns_rebinding_host_rejected` |
| SQL injection | Parameterised queries; scan IDs regex-validated | `test_scan_id_injection`, `test_sql_injection_in_query_params_is_inert` |
| Static-file path traversal | Resolved path must be inside `frontend/dist` | `test_spa_path_traversal` |
| Unsafe deserialisation / template injection | JSON/TOML/safe-YAML only; no pickle; no server-side templating of user data | — |
| Information disclosure | Generic errors with a reference ID, no stack traces; events store short metadata only | `test_upload_rejections`, `test_security_events_recorded` |
| Secret leakage in outputs | Redacted at detection time; raw values never stored or returned | `test_secrets_are_redacted_everywhere` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | `test_security_headers` |
| Vulnerable detector dependencies | All versions pinned; pip-audit and npm audit clean; react-router replaced by a 40-line router | TEST_RESULTS.md |

## Supply-chain attacks detected in scanned projects
Typosquatting (with corroboration rules), dependency confusion (`--extra-index-url`, scoped-registry mismatch,
non-default registries), install-time scripts, lockfile drift and integrity issues (missing/weak/mismatched hashes),
mutable git/URL references, compromised-release indicators (new packages, fresh releases, release bursts, publisher
changes, deprecation/yank), risky code in included package source, untrusted CI triggers, excessive token
permissions, unpinned actions, script injection, committed credentials.

## Residual risks and non-goals
- **No authentication or tenant isolation** — single-user local tool bound to 127.0.0.1. Network exposure needs authN/Z and TLS first.
- **Heuristics** can miss sophisticated malware (runtime-fetched stages, novel obfuscation) and produce false positives.
- **No cryptographic provenance verification**; attestations/signatures are reported as present/absent.
- **Upstream trust**: OSV/GHSA data is treated as authoritative; a poisoned advisory would be believed (but rendered safely).
- **Registry metadata** is owner-controlled and shown with its source.
- **Static reachability** misses dynamic `require`, reflection and framework-internal calls; "not imported" is not proof of non-use.
- **CPU within limits**: a crafted lockfile near the limits can cost seconds; scans run in threads with a timeout, not an OS sandbox.
- **Local storage** in `backend/data/` is unencrypted; protect the host account.
