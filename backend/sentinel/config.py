"""Central configuration: resource limits, provider endpoints, data paths."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", BACKEND_DIR / "data"))
DEMO_DIR = PROJECT_DIR / "demo"
DEMO_APP_DIR = DEMO_DIR / "demo-app"
FIXTURE_DIR = DEMO_DIR / "fixtures"
FRONTEND_DIST = PROJECT_DIR / "frontend" / "dist"


@dataclass(frozen=True)
class Limits:
    max_upload_bytes: int = 50 * 1024 * 1024          # compressed upload
    max_uncompressed_bytes: int = 200 * 1024 * 1024   # total bytes actually read from an archive
    max_file_bytes: int = 8 * 1024 * 1024             # any single file
    max_archive_entries: int = 50_000
    max_path_depth: int = 40
    max_path_length: int = 1024
    max_compression_ratio: int = 200
    max_packages: int = 20_000                        # graph size cap
    max_manifests: int = 200
    max_source_files_for_reachability: int = 4_000
    max_source_file_bytes: int = 512 * 1024
    max_secret_scan_files: int = 5_000
    max_registry_lookups: int = 120                   # packages enriched with registry metadata
    max_scorecard_lookups: int = 25
    max_remediation_registry_lookups: int = 40
    max_concurrent_scans: int = 2
    max_queued_scans: int = 6
    scan_timeout_seconds: int = 600
    http_timeout_seconds: float = 20.0
    http_max_response_bytes: int = 12 * 1024 * 1024
    http_retries: int = 2


LIMITS = Limits()

# Only these hosts are ever contacted. All are public, free, keyless endpoints.
PROVIDER_HOSTS = {
    "osv": "api.osv.dev",
    "npm": "registry.npmjs.org",
    "pypi": "pypi.org",
    "scorecard": "api.securityscorecards.dev",
    "kev": "www.cisa.gov",
    "epss": "api.first.org",
}
ALLOWED_HOSTS = frozenset(PROVIDER_HOSTS.values())

CACHE_TTL_SECONDS = {
    "osv_query": 6 * 3600,
    "osv_vuln": 24 * 3600,
    "npm": 12 * 3600,
    "pypi": 12 * 3600,
    "scorecard": 7 * 24 * 3600,
    "kev": 24 * 3600,
    "epss": 24 * 3600,
}

USER_AGENT = "SENTINEL-SC/1.0 (+supply-chain risk scanner; contact: local)"
