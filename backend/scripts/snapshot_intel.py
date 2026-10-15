"""Create the versioned offline intelligence snapshot used by the demo.

Runs a LIVE scan of demo/demo-app (plus remediation candidate checks), then exports every cache
entry that scan touched into demo/fixtures/intel-snapshot.json with its original retrieval time.
Offline / degraded-network demos then use this snapshot and are clearly labelled "fixture".

    python scripts/snapshot_intel.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel import db, engine  # noqa: E402
from sentinel.config import DEMO_APP_DIR, DEMO_DIR, FIXTURE_DIR  # noqa: E402
from sentinel.reposource import DirSource  # noqa: E402


def main():
    tmp = Path(tempfile.mkdtemp()) / "snap.db"
    db.init(tmp)  # fresh DB => everything in it was fetched live by this run
    res = engine.run_scan(DirSource(str(DEMO_APP_DIR)), offline=False)
    engine.whatif(res)
    # PR-review demo (base = main, head = risky pull request)
    extra = [engine.run_scan(DirSource(str(DEMO_DIR / "pr-review" / sub)), offline=False) for sub in ("base", "head")]
    osv = next(p for p in res["providers"] if p["name"] == "osv")
    if osv["status"] not in ("ok",) or res["summary"]["unverified_packages"] > 1:
        print("refusing to snapshot: OSV was not fully reachable", osv, file=sys.stderr)
        return 1
    rows = db.conn().execute("SELECT key, provider, fetched_at, value_json FROM intel_cache WHERE origin='live'").fetchall()
    entries = {r["key"]: {"provider": r["provider"], "fetched_at": r["fetched_at"], "value": json.loads(r["value_json"])}
               for r in rows}
    # The KEV catalogue is large; keep only the CVEs relevant to the demo to keep the fixture small.
    cves = {c for r in [res, *extra] for f in r["findings"] if f["kind"] == "vulnerability" for c in f["advisory"]["cves"]}
    if "kev:catalog" in entries:
        cat = entries["kev:catalog"]["value"]
        cat["cves"] = {k: v for k, v in cat["cves"].items() if k in cves}
        cat["note"] = "Trimmed to CVEs relevant to the demo project."
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    out = {
        "schema": "sentinel-sc/intel-snapshot@1",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "description": "Versioned snapshot of public intelligence (OSV, npm, PyPI, OpenSSF Scorecard, CISA KEV, FIRST EPSS) "
                       "retrieved live for demo/demo-app and demo/pr-review. Used only in offline mode or when a live provider fails; results "
                       "are labelled 'fixture' with the original retrieval time.",
        "entries": entries,
    }
    path = FIXTURE_DIR / "intel-snapshot.json"
    path.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    # expected findings for regression tests / judges
    expected = sorted({(res["packages"][f["package_id"]]["name"], res["packages"][f["package_id"]]["version"], f["advisory"]["id"])
                       for f in res["findings"] if f["kind"] == "vulnerability"})
    (FIXTURE_DIR / "expected-findings.json").write_text(json.dumps({
        "generated_at": out["created_at"], "source": "live OSV scan of demo/demo-app",
        "vulnerabilities": [{"package": a, "version": b, "advisory": c} for a, b, c in expected],
        "must_be_clean": ["dayjs"],
        "must_flag_signals": ["typosquat:lodahs", "install_script:lodahs", "source_patterns:lodahs", "ci_pwn_request"],
    }, indent=2), encoding="utf-8")
    print(f"wrote {path} ({path.stat().st_size // 1024} KiB, {len(entries)} entries); {len(expected)} expected vulnerabilities")
    return 0


if __name__ == "__main__":
    sys.exit(main())
