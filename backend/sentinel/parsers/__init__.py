"""Ecosystem detection and manifest dispatch.

Discovery pairs manifests with lockfiles in the same directory and prefers lockfiles (exact
versions). Every recognised file produces a `ParseOutcome`; recognised-but-unsupported files
are reported as "unsupported" so a scan never silently treats them as clean.
"""
from __future__ import annotations

import fnmatch
import posixpath

from ..config import LIMITS
from ..reposource import RepoSource
from . import npm, others, python
from .base import ManifestError, ParseContext, ParseOutcome

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__",
             "bower_components", ".tox", ".mypy_cache", "site-packages"}

# Coverage matrix exposed to the UI and docs. status: full | partial | unsupported
COVERAGE = [
    {"ecosystem": "npm", "file": "package-lock.json / npm-shrinkwrap.json (v1, v2, v3)", "status": "full",
     "notes": "Exact versions, integrity, install-script flags, dev/optional scopes, nested resolution."},
    {"ecosystem": "npm", "file": "yarn.lock (classic v1, berry)", "status": "full",
     "notes": "Exact versions and edges; dev/runtime inferred from package.json."},
    {"ecosystem": "npm", "file": "pnpm-lock.yaml (v5, v6, v9)", "status": "partial",
     "notes": "Root importer attached; other workspace importers listed but not separate components."},
    {"ecosystem": "npm", "file": "package.json (without lockfile)", "status": "partial",
     "notes": "Direct deps only; ranges are not resolved and are reported as unverified."},
    {"ecosystem": "PyPI", "file": "poetry.lock (+ pyproject.toml)", "status": "full", "notes": "Exact versions, hashes, edges."},
    {"ecosystem": "PyPI", "file": "Pipfile.lock", "status": "partial", "notes": "Exact versions and hashes; no edges recorded by format."},
    {"ecosystem": "PyPI", "file": "requirements*.txt / constraints*.txt", "status": "partial",
     "notes": "Pins, hashes, -r/-c includes, index URLs; edges only from pip-compile '# via' annotations."},
    {"ecosystem": "PyPI", "file": "pyproject.toml (PEP 621 / Poetry, without lock)", "status": "partial", "notes": "Declared ranges only."},
    {"ecosystem": "Go", "file": "go.mod + go.sum", "status": "partial",
     "notes": "All required modules with exact versions and hashes; indirect module parents not recorded by go.mod."},
    {"ecosystem": "crates.io", "file": "Cargo.lock (+ Cargo.toml)", "status": "full", "notes": "Exact versions, checksums, edges, workspace crates."},
    {"ecosystem": "crates.io", "file": "Cargo.toml (without lock)", "status": "partial", "notes": "Declared requirements only."},
    {"ecosystem": "Maven", "file": "pom.xml", "status": "partial", "notes": "Direct deps with property substitution; no transitive resolution."},
    {"ecosystem": "Maven", "file": "gradle.lockfile", "status": "partial", "notes": "Exact coordinates; no edges."},
    {"ecosystem": "Maven", "file": "build.gradle / build.gradle.kts", "status": "partial", "notes": "Literal coordinates only (pattern-based)."},
    {"ecosystem": "NuGet", "file": "packages.lock.json", "status": "full", "notes": "Exact versions, content hashes, edges."},
    {"ecosystem": "NuGet", "file": "*.csproj / packages.config", "status": "partial", "notes": "Direct PackageReference entries only."},
    {"ecosystem": "SBOM", "file": "CycloneDX JSON (1.2 - 1.6)", "status": "full", "notes": "Components via purl, dependency graph, hashes, licenses."},
    {"ecosystem": "SBOM", "file": "CycloneDX XML, SPDX", "status": "unsupported", "notes": "Detected and reported, not parsed."},
    {"ecosystem": "Go", "file": "go.work, vendor/modules.txt", "status": "unsupported", "notes": "Detected and reported, not parsed."},
    {"ecosystem": "PyPI", "file": "setup.py / setup.cfg", "status": "unsupported", "notes": "setup.py is executable code and is never run."},
]

UNSUPPORTED_PATTERNS = {
    "setup.py": ("PyPI", "setup.py is executable code; it is never run, so dependencies are not extracted."),
    "setup.cfg": ("PyPI", "setup.cfg install_requires is not parsed."),
    "go.work": ("Go", "Go workspaces are not parsed; each go.mod is scanned individually."),
    "Gemfile.lock": ("RubyGems", "RubyGems is not supported in this version."),
    "composer.lock": ("Packagist", "Composer/PHP is not supported in this version."),
    "*.spdx.json": ("SBOM", "SPDX SBOMs are not supported; export CycloneDX instead."),
    "bom.xml": ("SBOM", "CycloneDX XML is not supported; use CycloneDX JSON."),
    "Directory.Packages.props": ("NuGet", "Central package management props are not parsed."),
}


def _skip(path: str) -> bool:
    parts = path.split("/")[:-1]
    return any(p in SKIP_DIRS for p in parts)


def discover(src: RepoSource) -> list[str]:
    return [p for p in src.list_files() if not _skip(p)]


def is_cyclonedx_name(base: str) -> bool:
    b = base.lower()
    return b.endswith((".cdx.json", ".cyclonedx.json")) or b in ("bom.json", "sbom.json", "cyclonedx.json")


def parse_repository(src: RepoSource, ctx: ParseContext, progress=None) -> list[ParseOutcome]:
    files = discover(src)
    by_dir: dict[str, set[str]] = {}
    for f in files:
        by_dir.setdefault(posixpath.dirname(f), set()).add(posixpath.basename(f))
    outcomes = ctx.outcomes
    manifests = 0

    def run(path, eco, kind, fn, *args):
        nonlocal manifests
        manifests += 1
        if manifests > LIMITS.max_manifests:
            outcomes.append(ParseOutcome(path, eco, kind, "-", "skipped", 0, "Manifest limit reached."))
            return
        try:
            out = fn(src, path, ctx, *args)
            if out:
                outcomes.append(out)
        except ManifestError as exc:
            outcomes.append(ParseOutcome(path, eco, kind, "-", "error", 0, str(exc)))
        except (RecursionError, MemoryError):
            outcomes.append(ParseOutcome(path, eco, kind, "-", "error", 0, f"{path}: input too complex to parse safely"))
        if len(ctx.graph.packages) > LIMITS.max_packages:
            raise ManifestError("Dependency graph exceeds the maximum supported size.")
        if progress:
            progress(path)

    for d in sorted(by_dir):
        names = by_dir[d]
        j = (lambda n: f"{d}/{n}" if d else n)

        # ---------------- npm
        if ".npmrc" in names:
            npm.parse_npmrc(src, j(".npmrc"), ctx)
        lock = next((n for n in ("npm-shrinkwrap.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml") if n in names), None)
        meta = None
        if "package.json" in names:
            try:
                meta = npm.parse_package_json(src, j("package.json"), ctx, has_lock=bool(lock))
                outcomes.append(ParseOutcome(j("package.json"), "npm", "manifest", "package.json",
                                             "parsed" if lock else "partial", len(meta["declared"]),
                                             "Declared dependencies read" + ("; versions taken from lockfile." if lock else
                                                                             "; no lockfile, versions unresolved."),
                                             [] if lock else ["No lockfile: installed versions and transitive dependencies are unknown."]))
            except ManifestError as exc:
                outcomes.append(ParseOutcome(j("package.json"), "npm", "manifest", "package.json", "error", 0, str(exc)))
        if lock:
            fn = {"npm-shrinkwrap.json": npm.parse_package_lock, "package-lock.json": npm.parse_package_lock,
                  "yarn.lock": npm.parse_yarn_lock, "pnpm-lock.yaml": npm.parse_pnpm_lock}[lock]
            run(j(lock), "npm", "lockfile", fn, meta)
            for extra in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                if extra in names and extra != lock and not (lock == "npm-shrinkwrap.json" and extra == "package-lock.json"):
                    outcomes.append(ParseOutcome(j(extra), "npm", "lockfile", "-", "skipped", 0,
                                                 f"Multiple lockfiles in one directory; {lock} was used. "
                                                 "Conflicting lockfiles are a resolution-ambiguity risk."))
                    ctx.unpinned.append({"file": j(extra), "name": "(project)", "spec": f"{lock} + {extra}", "ecosystem": "npm",
                                         "reason": "multiple lockfiles - package manager resolution is ambiguous"})
        elif meta is not None:
            run(j("package.json") + "#deps", "npm", "manifest", lambda s, p, c: (npm.add_manifest_only(c, j("package.json"), meta), None)[1])
            ctx.missing_lockfiles.append({"manifest": j("package.json"), "ecosystem": "npm"})

        # ---------------- Python
        if "poetry.lock" in names:
            run(j("poetry.lock"), "PyPI", "lockfile", python.parse_poetry_lock)
        elif "Pipfile.lock" in names:
            run(j("Pipfile.lock"), "PyPI", "lockfile", python.parse_pipfile_lock)
        elif "pyproject.toml" in names and not any(fnmatch.fnmatch(n, "requirements*.txt") for n in names):
            run(j("pyproject.toml"), "PyPI", "manifest", python.parse_pyproject_only)
        if "Pipfile" in names and "Pipfile.lock" not in names:
            outcomes.append(ParseOutcome(j("Pipfile"), "PyPI", "manifest", "Pipfile", "unsupported", 0,
                                         "Pipfile without Pipfile.lock: lock the environment to scan exact versions."))
            ctx.missing_lockfiles.append({"manifest": j("Pipfile"), "ecosystem": "PyPI"})
        for n in sorted(names):
            low = n.lower()
            if low.endswith(".txt") and (low.startswith("requirements") or low.startswith("constraints")
                                          or low in ("requirements-dev.txt", "dev-requirements.txt")):
                run(j(n), "PyPI", "manifest", python.parse_requirements)

        # ---------------- Go / Rust
        if "go.mod" in names:
            run(j("go.mod"), "Go", "manifest", others.parse_go_mod)
        if "Cargo.lock" in names:
            run(j("Cargo.lock"), "crates.io", "lockfile", others.parse_cargo_lock)
        elif "Cargo.toml" in names:
            run(j("Cargo.toml"), "crates.io", "manifest", others.parse_cargo_toml_only)

        # ---------------- JVM
        if "pom.xml" in names:
            run(j("pom.xml"), "Maven", "manifest", others.parse_pom)
        if "gradle.lockfile" in names:
            run(j("gradle.lockfile"), "Maven", "lockfile", others.parse_gradle_lockfile)
        else:
            for n in ("build.gradle", "build.gradle.kts"):
                if n in names:
                    run(j(n), "Maven", "manifest", others.parse_gradle_build)

        # ---------------- .NET
        if "packages.lock.json" in names:
            run(j("packages.lock.json"), "NuGet", "lockfile", others.parse_nuget_lock)
        else:
            for n in sorted(names):
                if n.endswith((".csproj", ".fsproj", ".vbproj")) or n == "packages.config":
                    run(j(n), "NuGet", "manifest", others.parse_csproj)

        # ---------------- SBOM
        for n in sorted(names):
            if is_cyclonedx_name(n):
                run(j(n), "SBOM", "sbom", others.parse_cyclonedx)

        # ---------------- recognised but unsupported
        for n in sorted(names):
            for pat, (eco, why) in UNSUPPORTED_PATTERNS.items():
                if fnmatch.fnmatch(n, pat):
                    outcomes.append(ParseOutcome(j(n), eco, "manifest", "-", "unsupported", 0, why))
    return outcomes
