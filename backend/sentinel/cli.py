"""Command-line interface / CI security gate.

    python -m sentinel scan <dir | file.zip | manifest | sbom.json | github-url> [--offline] [--policy policy.json]
                            [--json out.json] [--html out.html] [--sbom out.cdx.json] [--strict-warn]

    python -m sentinel review --base <target> --head <target> [--offline] [--policy policy.json]
                              [--markdown review.md] [--json review.json] [--strict-warn]

`review` compares two versions of a project (e.g. main vs a pull request) and gates only on risk the
change INTRODUCES. Exit codes (both commands): 0 pass/warn, 1 policy violation, 2 error,
3 warnings with --strict-warn.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import db, engine, policy, report, review, sbom
from .config import FIXTURE_DIR
from .reposource import DirSource, RepoSource, SingleFileSource, UnsafeInputError, ZipSource


class CliError(Exception):
    pass


def load_source(target: str, offline: bool, quiet: bool) -> RepoSource:
    """Directory, .zip, single manifest/SBOM file, or a public GitHub URL."""
    if re.match(r"^(https?://)?(www\.)?github\.com/", target, re.I):
        if offline:
            raise CliError("scanning a GitHub URL needs network access (remove --offline)")
        from .github import GitHubImportError, fetch_repository, parse_github_url
        try:
            src, meta = fetch_repository(parse_github_url(target), None if quiet else (lambda m: print(f"  {m}", file=sys.stderr)))
        except GitHubImportError as exc:
            raise CliError(str(exc)) from exc
        if not quiet:
            print(f"  scanning {meta['repository']} @ {meta['commit']}", file=sys.stderr)
        return src
    t = Path(target)
    if t.is_dir():
        return DirSource(str(t))
    if t.suffix.lower() == ".zip":
        return ZipSource(t.read_bytes(), t.name)
    if t.is_file():
        return SingleFileSource(t.name, t.read_bytes())
    raise CliError(f"target not found: {target}")


def _run(src: RepoSource, offline: bool, quiet: bool, pol, label: str = "") -> dict:
    def prog(p):
        if not quiet:
            print(f"\r{label}[{p['percent']:5.1f}%] {p['stage'] or ''}".ljust(60), end="", file=sys.stderr, flush=True)
    result = engine.run_scan(src, offline=offline, progress_cb=prog, policy=pol, scan_id="cli")
    if not quiet:
        print(file=sys.stderr)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description="SENTINEL-SC supply-chain scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--offline", action="store_true", help="use only cached/fixture intelligence (no network)")
    common.add_argument("--policy", help="policy JSON file (defaults to built-in policy)")
    common.add_argument("--strict-warn", action="store_true", help="exit 3 when the verdict is 'warn'")
    common.add_argument("--load-fixture", action="store_true", help="import demo intelligence snapshot first")
    common.add_argument("--quiet", action="store_true")

    s = sub.add_parser("scan", parents=[common], help="scan a directory, .zip, manifest, CycloneDX SBOM or GitHub URL")
    s.add_argument("target")
    s.add_argument("--json", dest="json_out", help="write full JSON result")
    s.add_argument("--html", dest="html_out", help="write HTML report")
    s.add_argument("--sbom", dest="sbom_out", help="write CycloneDX 1.5 SBOM (with VEX analysis)")

    r = sub.add_parser("review", parents=[common], help="PR dependency review: compare base and head, gate on new risk")
    r.add_argument("--base", required=True, help="base version (directory, .zip, file or GitHub URL)")
    r.add_argument("--head", required=True, help="head/PR version (directory, .zip, file or GitHub URL)")
    r.add_argument("--markdown", dest="md_out", help="write the review as Markdown (e.g. for a PR comment)")
    r.add_argument("--json", dest="json_out", help="write the review as JSON")
    args = ap.parse_args(argv)

    db.init(Path(os.environ["SENTINEL_DB"]) if os.environ.get("SENTINEL_DB") else None)
    if args.load_fixture:
        from .intel import load_fixture
        snap = FIXTURE_DIR / "intel-snapshot.json"
        if snap.exists():
            load_fixture(snap)
    try:
        pol = policy.validate(json.loads(Path(args.policy).read_text(encoding="utf-8"))) if args.policy else None
        if args.cmd == "review":
            base = _run(load_source(args.base, args.offline, args.quiet), args.offline, args.quiet, pol, "base ")
            head = _run(load_source(args.head, args.offline, args.quiet), args.offline, args.quiet, pol, "head ")
            return _finish_review(review.review(base, head, pol), args)
        result = _run(load_source(args.target, args.offline, args.quiet), args.offline, args.quiet, pol)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (UnsafeInputError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return _finish_scan(result, args)


def _finish_scan(result: dict, args) -> int:
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
    return _exit(g["verdict"], args, s["status"] == "failed")


def _finish_review(rv: dict, args) -> int:
    md = review.to_markdown(rv)
    if args.md_out:
        Path(args.md_out).write_text(md, encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(rv, indent=2), encoding="utf-8")
    s, g = rv["summary"], rv["gate"]
    print(f"SENTINEL-SC review  added={s['added']} changed={s['changed']} (downgrades {s['downgrades']}) removed={s['removed']}  "
          f"new_vulnerabilities={s['new_vulnerabilities']} new_signals={s['new_signals']} resolved={s['resolved']} "
          f"attention={s['attention']}")
    print(f"REVIEW: {g['verdict'].upper()}  ({len(g['violations'])} violation(s))")
    for v in g["violations"][:20]:
        print(f"  x [{v['rule']}] {v.get('package') or v.get('file') or ''} {v['message']}")
    for a in rv["attention"][:20]:
        print(f"  ! [{a['type']}] {a.get('package') or ''} {a['detail']}")
    return _exit(g["verdict"], args, False)


def _exit(verdict: str, args, failed: bool) -> int:
    if verdict == "fail":
        return 1
    if verdict == "warn" and args.strict_warn:
        return 3
    if failed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
