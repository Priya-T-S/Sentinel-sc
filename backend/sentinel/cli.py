"""Command-line interface / CI security gate.

    python -m sentinel scan <dir|file.zip|sbom.json> [--offline] [--policy policy.json]
                            [--json out.json] [--html out.html] [--sbom out.cdx.json] [--strict-warn]

Exit codes: 0 pass/warn, 1 policy violation, 2 scan error, 3 warnings with --strict-warn.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import db, engine, policy, report, sbom
from .config import FIXTURE_DIR
from .reposource import DirSource, SingleFileSource, UnsafeInputError, ZipSource


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description="SENTINEL-SC supply-chain scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a directory, .zip archive, manifest or CycloneDX SBOM")
    s.add_argument("target")
    s.add_argument("--offline", action="store_true", help="use only cached/fixture intelligence (no network)")
    s.add_argument("--policy", help="policy JSON file (defaults to built-in policy)")
    s.add_argument("--json", dest="json_out", help="write full JSON result")
    s.add_argument("--html", dest="html_out", help="write HTML report")
    s.add_argument("--sbom", dest="sbom_out", help="write CycloneDX 1.5 SBOM (with VEX analysis)")
    s.add_argument("--strict-warn", action="store_true", help="exit 3 when the gate verdict is 'warn'")
    s.add_argument("--load-fixture", action="store_true", help="import demo intelligence snapshot before scanning")
    s.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    db.init(Path(os.environ["SENTINEL_DB"]) if os.environ.get("SENTINEL_DB") else None)
    if args.load_fixture:
        from .intel import load_fixture
        snap = FIXTURE_DIR / "intel-snapshot.json"
        if snap.exists():
            load_fixture(snap)
    try:
        t = Path(args.target)
        if t.is_dir():
            src = DirSource(str(t))
        elif t.suffix.lower() == ".zip":
            src = ZipSource(t.read_bytes(), t.name)
        elif t.is_file():
            src = SingleFileSource(t.name, t.read_bytes())
        else:
            print("error: target not found", file=sys.stderr)
            return 2
        pol = None
        if args.policy:
            pol = policy.validate(json.loads(Path(args.policy).read_text(encoding="utf-8")))

        def prog(p):
            if not args.quiet:
                print(f"\r[{p['percent']:5.1f}%] {p['stage'] or ''}".ljust(60), end="", file=sys.stderr, flush=True)
        result = engine.run_scan(src, offline=args.offline, progress_cb=prog, policy=pol, scan_id="cli")
        if not args.quiet:
            print(file=sys.stderr)
    except (UnsafeInputError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.html_out:
        Path(args.html_out).write_text(report.render_html(result), encoding="utf-8")
    if args.sbom_out:
        Path(args.sbom_out).write_text(json.dumps(sbom.export_cyclonedx(result), indent=2), encoding="utf-8")
    s = result["summary"]
    g = result["policy"]
    print(f"SENTINEL-SC  status={s['status']}  packages={s['packages']} (direct {s['direct']})  "
          f"vulnerabilities={s['vulnerabilities']} [C{s['severity']['critical']} H{s['severity']['high']} "
          f"M{s['severity']['medium']} L{s['severity']['low']}]  suspicious={s['suspicious_signals']}  "
          f"unverified={s['unverified_packages']}")
    for p in result["providers"]:
        if p["status"] not in ("not_used",):
            print(f"  provider {p['label']:<20} {p['status']:<9} live={p['live_calls']} cache={p['cache_hits']} "
                  f"stale={p['stale_hits']} fixture={p['fixture_hits']} unavailable={p['misses']}")
    print(f"GATE: {g['verdict'].upper()}  ({len(g['violations'])} violation(s), {g['warning_count']} warning(s))")
    for v in g["violations"][:20]:
        print(f"  x [{v['rule']}] {v.get('package') or v.get('file') or ''} {v['message']}")
    if g["verdict"] == "fail":
        return 1
    if g["verdict"] == "warn" and args.strict_warn:
        return 3
    if s["status"] == "failed":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
