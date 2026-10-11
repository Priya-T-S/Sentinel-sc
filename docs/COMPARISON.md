# Beyond a conventional dependency scanner

A conventional scanner (e.g. `npm audit`, a basic OSV/SCA check) outputs a list: *package X version Y has CVE Z,
upgrade to W*. SENTINEL-SC keeps that deterministic core and adds:

| Capability | Conventional scanner | SENTINEL-SC |
|---|---|---|
| Version matching | Provider match only | Provider match **plus** independent local range evaluation; disagreements flagged |
| Duplicate advisories | Often listed twice (GHSA + CVE / aliases) | Alias groups merged: one flaw, one finding, one score |
| Provider outage | Often "0 vulnerabilities" | *Not verified* per package; gate fails closed; stale/fixture data labelled with age |
| How risk arrives | Package name | Every app → … → package path, blast radius, affected components |
| Reachability | None | Imports and call sites of advisory-named symbols with file:line; "installed ≠ reachable" |
| Prioritisation | Severity | Separate intrinsic / exposure / confidence / priority with a factor-by-factor explanation; KEV + EPSS |
| Fixes | "Upgrade to ≥ fixed" | Smallest version fixing **all** advisories, re-checked on OSV; declared-range and parent-range checks; transitive fixes resolved through registry ranges along every path; one combined manifest diff; what-if comparison |
| Malicious-package risk | None | Typosquat (with corroboration), install scripts, static source-pattern inspection, provenance/signature presence, integrity mismatch, dependency confusion, release-pattern and maintenance signals — labelled as heuristics |
| Build pipeline risk | None | GitHub Actions: pwn-request, script injection, permissions, unpinned actions; secret exposure (redacted) |
| Prevention | Exit code | Deterministic, auditable policy (confidence thresholds, accepted-risk list, license rules), CI workflow, CycloneDX SBOM + VEX, risk-regression diff between scans |
| Privacy | Varies | Only package identifiers leave the machine; offline mode |
