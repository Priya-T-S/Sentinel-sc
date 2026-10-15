// Typed contracts for the SENTINEL-SC REST API (mirrors backend/sentinel/engine.py output).

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'
export type FindingKind = 'vulnerability' | 'suspicious' | 'integrity' | 'maintenance' | 'hygiene' | 'secret' | 'ci'
export type ReachLevel = 'symbol_call' | 'imported' | 'transitive_imported' | 'transitive' | 'declared_not_imported' | 'unknown'
export type RemState = 'safe_candidate' | 'requires_review' | 'no_verified_fix' | 'insufficient_information'

export interface Evidence {
  observation: string
  source: string
  url?: string
  retrieved_at?: string | null
  origin?: string
  file?: string
  line?: number
  snippet?: string
  decoded_preview?: string | null
}

export interface ScoreFactor { component: string; factor: string; value: unknown; effect: string; evidence: string | null }
export interface Scores {
  intrinsic: number | null
  exposure: number | null
  confidence: number
  confidence_label: string
  priority: number | null
  priority_bucket: string
  factors: ScoreFactor[]
}

export interface Reachability {
  level: ReachLevel
  label: string
  explanation: string
  needed?: string
  symbols_considered?: string[]
  symbol_source?: string
  evidence: { kind?: string; file?: string; line?: number; snippet?: string; symbol?: string; how?: string; is_test?: boolean; via?: string[] }[]
}

export interface Advisory {
  id: string
  ids: string[]
  aliases: string[]
  cves: string[]
  summary: string
  details: string
  published?: string
  modified?: string
  cwes: string[]
  references: { type: string; url: string }[]
  affected_ranges: string[]
  fixed_versions: string[]
  first_fixed?: string | null
  applies_to_installed: boolean | null
  source_url: string
  database_source?: string | null
  retrieved_at?: string | null
  origin: string[]
  severity: Severity
  severity_basis: string
  cvss_score: number | null
  cvss_vector: string | null
}

export interface Finding {
  id: string
  fingerprint: string
  kind: FindingKind
  category: string
  signal?: string
  package_id?: string
  file?: string
  line?: number
  title: string
  severity: Severity
  confidence: string
  verified: boolean
  observation?: string
  explanation?: string
  advisory?: Advisory
  evidence: Evidence[]
  paths?: string[][]
  blast_radius?: { roots: number; root_ids: string[]; dependents: number; direct_dependencies: string[]; depth: number | null; path_count: number; path_known: boolean }
  reachability?: Reachability
  exploitation?: { kev: { cve: string; dateAdded?: string } | null; epss: { epss: number; percentile: number; date?: string } | null; summary: string; kev_checked?: boolean }
  remediation?: { state: RemState; target: string | null; fix_confidence: string; major_change?: boolean | null }
  scores: Scores
  review?: { status: 'confirmed' | 'corrected'; corrections: { check: string; before: unknown; after: unknown; reason: string }[] }
  ai_explanation?: { finding_id: string; plain_explanation: string; why_it_matters_here: string; investigation_steps: string[]; cited_facts: string[]; model: string; label: string }
}

export interface TrustItem { key: string; label: string; status: string; detail: string; source: string }

export interface PackageInfo {
  id: string
  name: string
  version: string | null
  ecosystem: string
  purl: string | null
  direct: boolean
  scope: string
  depth: number | null
  source_file: string
  declared_spec: string | null
  version_exact: boolean
  integrity: string | null
  resolved: string | null
  source_type: string
  has_install_script: boolean | null
  license: string | null
  vuln_status: 'checked' | 'unverified' | 'not_applicable'
  vuln_status_code?: string | null
  vuln_status_reason: string
  osv_origin: string | null
  osv_checked_at: string | null
  finding_ids: string[]
  vulnerability_count: number
  signal_count: number
  max_severity: Severity | null
  risk: { intrinsic: number | null; exposure: number | null; priority: number | null; priority_bucket: string }
  trust: { items: TrustItem[]; scorecard: { score: number; date: string; checks: { name: string; score: number; reason: string }[] } | null }
  registry: null | { available: boolean; origin: string; retrieved_at?: string; created?: string; latest?: string; published?: string; license?: string; description?: string; repository?: string; maintainers?: string[]; deprecated?: string | null; version_count?: number; recent_versions?: { version: string; published: string }[] }
  imported_in: { file: string; line: number; is_test: boolean }[]
  provenance?: Provenance | null
  dependents: number
  dependencies: number
}

export interface Plan {
  package_id: string
  package: string
  ecosystem: string
  installed: string | null
  direct: boolean
  scope: string
  findings: string[]
  advisories: string[]
  state: RemState
  fix_confidence: 'verified' | 'candidate' | 'unverified'
  target: string | null
  minimum_fixed?: string
  major_change?: boolean | null
  reason?: string
  candidates_checked?: { version: string; known_advisories: string[] | null }[]
  remaining_advisories?: string[] | null
  unfixed_advisories?: string[]
  evidence?: { observation: string; source: string }[]
  actions: { step: string; command: string; why: string }[]
  compatibility: { check: string; result: string; detail: string }[]
  paths: string[][]
  patch: { file: string; diff: string; note: string; applied: boolean } | null
  alternatives: { action: string; detail: string }[]
  resolution_upgrades?: { direct: string; from: string; version: string; resolved_versions: string[]; chain: string[]; major_change: boolean }[]
}

export interface Provider {
  name: string; label: string; purpose: string; data_sent: string; status: string
  live_calls: number; cache_hits: number; stale_hits: number; fixture_hits: number; misses: number
  errors: string[]; oldest_data: number | null; newest_data: number | null
}

export interface Outcome { file: string; ecosystem: string; kind: string; parser: string; status: string; packages: number; message: string; limitations: string[] }

export interface Summary {
  status: string
  packages: number; direct: number; transitive: number; components: number
  vulnerabilities: number; vulnerable_packages: number; verified_vulnerabilities: number
  severity: Record<'critical' | 'high' | 'medium' | 'low' | 'unknown', number>
  suspicious_signals: number; integrity_signals: number; maintenance_signals: number; hygiene_findings: number
  secret_findings: number; ci_findings: number
  by_kind: Record<string, number>
  by_ecosystem: Record<string, { packages: number; vulnerable: number; findings: number; unverified: number }>
  reachability: Record<string, number>
  priority_buckets: Record<string, number>
  unverified_packages: number
  known_exploited: number
  provenance?: Record<string, number>
  fixable: number; fix_verified: number
  max_priority: number | null
  top_priorities: { id: string; title: string; kind: FindingKind; severity: Severity; package_id?: string; priority: number | null; bucket: string; remediation?: string }[]
  data_freshness: { osv_status: string; oldest: string | null; newest: string | null; origins: Record<string, number> }
}

export interface PolicyResult {
  verdict: 'pass' | 'warn' | 'fail'
  exit_code: number
  violations: { rule: string; message: string; package?: string; advisory?: string; severity?: string; file?: string }[]
  warnings: { rule: string; message: string; package?: string }[]
  warning_count: number
  policy: Record<string, unknown>
  notes: string
}

export interface ScanResult {
  schema: string
  scan: { id: string; source_name: string; engine_version: string; offline: boolean; started_at: string; finished_at: string; duration_seconds: number; status: string; fatal_error: string | null; source?: SourceInfo | null }
  coverage: { outcomes: Outcome[]; input: { files_seen: number; rejected: { path: string; reason: string }[]; skipped_large: number; bytes_read: number }; source_index: { files_scanned: number; languages: Record<string, number>; truncated: boolean }; unverified_packages: number; intel_unavailable_packages?: number; no_exact_version_packages?: number }
  providers: Provider[]
  privacy: { data_sent: { provider: string; data: string; calls: number }[]; never_sent: string }
  stats: { packages: number; direct: number; transitive: number; edges: number; roots: number; max_depth: number; by_ecosystem: Record<string, number> }
  remediation: { plans: Plan[]; combined_patch: { files: { file: string; diff: string; note: string; changes?: { type: string; package: string; to: string }[] }[] } | null }
  summary: Summary
  policy: PolicyResult
  package_count: number
  roots: { id: string; name: string; ecosystem: string; manifest?: string; lockfile?: string | null }[]
  orchestration?: Orchestration
  review?: ReviewReport
  ai?: AIReport
}

export interface AgentRunInfo {
  agent: string; title: string; role: string; status: string; started_at: number | null; duration: number | null
  outputs: Record<string, unknown>; notes: string[]; error: string | null
}
export interface Orchestration {
  plan: { step: number; agents: string[]; parallel: boolean; needs: string[]; why: string }[]
  agents: AgentRunInfo[]
  messages: { t: number; from: string; to: string; text: string }[]
  principle: string
}
export interface ReviewCheck { description: string; checked: number; failed: number }
export interface ReviewReport {
  verdict: 'approved' | 'approved_with_corrections' | 'rejected'
  statement: string
  pass1: Record<string, ReviewCheck>
  pass2: Record<string, ReviewCheck>
  corrections: { check: string; target: string | null; before: unknown; after: unknown; reason: string }[]
  conflicts: { type: string; package_id: string; package: string; detail: string; suggestion: string }[]
}
export interface AIReport {
  enabled: boolean; status?: 'ok' | 'error' | 'declined'; reason?: string; error?: string; model?: string; served_by?: string
  summary?: string; explained?: number; conflict_notes?: { conflict_index: number; note: string; next_steps: string[] }[]
  guard_rejections?: Record<string, unknown>[]; input_tokens?: number; output_tokens?: number; estimated_cost_usd?: number
  seconds?: number; data_sent?: string; shared_code_snippets?: boolean; refusal_category?: string | null
}

export interface ScanRow {
  id: string; created_at: number; finished_at: number | null; status: string; source_name: string; source_kind: string; is_demo: boolean; error: string | null
  summary: null | { status: string; packages: number; direct: number; vulnerabilities: number; vulnerable_packages: number; severity: Summary['severity']; suspicious_signals: number; unverified_packages: number; policy: string; max_priority: number | null; ecosystems: string[]; offline: boolean; findings: number }
}

export interface ScanStatus extends ScanRow {
  progress: null | { percent: number; stage: string | null; stages: { key: string; label: string; status: string; detail: string; agent?: string }[]; elapsed: number }
}

export interface GraphNode {
  id: string; type: 'root' | 'package'; name: string; version?: string | null; ecosystem: string; direct?: boolean; scope?: string
  depth: number | null; max_severity?: Severity | null; vulnerability_count?: number; signal_count?: number; priority?: number | null; vuln_status?: string; dependents?: number; manifest?: string
}
export interface GraphEdge { from: string; to: string; relation: string; spec: string | null; scope: string | null }

export interface WhatIfResult {
  label: string
  changes: { package_id: string; name: string; from: string | null; to: string; before: number; after: number | null; status: string; remaining?: string[] }[]
  before: { vulnerabilities: number; severity: Summary['severity']; max_priority: number; total_exposure: number; p1: number }
  after: { vulnerabilities: number; severity: Summary['severity']; max_priority: number; total_exposure: number; p1: number }
  resolved: { id: string; advisory: string; package: string }[]
  remaining: { advisory: string; package_id: string; severity: Severity }[]
  unverified_changes: string[]
  limitations: string[]
  generated_at: string
}

export interface SourceInfo {
  type: string
  repository: string
  url: string
  requested_ref: string | null
  resolved_ref: string
  commit: string
  commit_url: string
  commit_date: string | null
  archive_bytes: number
  fetched_at: string
}

export interface Provenance {
  status: 'verified' | 'invalid' | 'repo_mismatch' | 'absent' | 'unsupported' | 'unavailable'
  reason?: string
  repository?: string
  commit?: string
  workflow?: string
  ref?: string
  builder?: string
  run_url?: string
  rekor_log_index?: number
  rekor_url?: string
  signed_at?: string
  trust_root?: string
  digest_source?: string
  declared_repository?: string
  origin?: string
}
