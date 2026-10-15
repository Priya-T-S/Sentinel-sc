# Risk scoring

Implemented in [backend/sentinel/scoring.py](../backend/sentinel/scoring.py); the same text is shown in
**Settings → Scoring model**, and every finding lists its factors under **Why this score?**.

Each finding has four separate values. Missing inputs remain `null` ("Unknown") — never zero.

| Value | Meaning | Computation |
|---|---|---|
| **Intrinsic risk** (0–100) | How bad the issue is in the package | CVSS v3 base score × 10 (computed locally from the vector with the FIRST formula); else advisory rating band (critical 95, high 80, medium 55, low 25); +10 if in CISA KEV. Heuristics: fixed bands (high 70, medium 45, low 20, info 5). |
| **Application exposure** (0–100) | How much it matters for this app | intrinsic × reachability weight × scope weight × applicability weight |
| **Confidence** (0–100 + label) | How sure the assessment is | 50 base; +20 exact version from lockfile; +15 advisory details retrieved; +10 local range check agrees; −20 disagrees; −15 stale/fixture data; −10 reachability unknown |
| **Remediation priority** (P1–P4) | What to fix first | exposure + 10 if a fix is OSV-verified + 15 if KEV + 10 × EPSS; P1 ≥ 75, P2 ≥ 55, P3 ≥ 30 |

Weights (an explicit, auditable ordering of evidence strength — not a statistical model):

| Reachability | weight | Scope | weight |
|---|---|---|---|
| symbol_call (advisory symbol called) | 1.0 | runtime | 1.0 |
| imported | 0.85 | optional / peer / unknown | 0.8 |
| transitive_imported | 0.7 | build | 0.6 |
| unknown (no source) | 0.7 | dev / test | 0.35 |
| transitive | 0.55 | | |
| declared_not_imported | 0.4 | | |

Range check disagreeing with OSV applies × 0.6. Heuristic priority = exposure × confidence (0.8 / 0.6 / 0.4).

**Reviewed before scoring:** the Independent Security Reviewer runs before scores are computed, so a claim it
downgrades (e.g. "fix verified" without an OSV re-check, "call-site evidence" without a file and line) is scored on
the corrected value.

**No double counting:** aliased advisories (GHSA + CVE + duplicate GHSA) are merged into one finding before scoring;
package-level risk is the **maximum** of its findings, never a sum; dependency depth/breadth is shown as blast radius
but not multiplied in (reachability already captures it).

**Limitations:** weights are judgement calls documented here; EPSS and KEV only exist for CVE-aliased advisories;
CVSS v4-only advisories use the qualitative rating.
