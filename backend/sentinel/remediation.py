"""Evidence-backed remediation planning.

For each vulnerable package:
  1. Target = smallest version that is >= every advisory's first fixed version (fixes all fixable advisories).
  2. Candidates = registry versions >= target (stable only), preferring the installed major line.
     Each candidate is re-queried on OSV; the first with NO known advisories is "verified".
  3. Compatibility: compare the candidate to the declared range (direct deps) or to every parent's
     dependency range (transitive deps). If a parent's range excludes the fix, search the parent's
     registry history for the smallest parent release whose range admits it; else propose an override.
  4. A unified diff is generated against the manifest *in memory*; the repository is never modified.

Remediation states:  safe_candidate | requires_review | no_verified_fix | insufficient_information
Fix confidence:      verified (OSV re-check clean) | candidate (advisory fixed version, not re-checked or
                     other advisories remain) | unverified (no authoritative fix data)
"""
from __future__ import annotations

import difflib
import json
import re
from typing import Optional

from . import versions
from .intel import IntelContext
from .intel import osv as osv_provider
from .intel.registry import npm_metadata, pypi_metadata
from .models import DependencyGraph, Package
from .reposource import RepoSource

MAX_CANDIDATES = 12


def _registry_versions(ictx: IntelContext, pkg: Package, meta_cache: dict) -> Optional[list[str]]:
    key = (pkg.ecosystem, pkg.name)
    if key not in meta_cache:
        meta = None
        if pkg.ecosystem == "npm":
            meta, _, _ = npm_metadata(ictx, pkg.name)
        elif pkg.ecosystem == "PyPI":
            meta, _, _ = pypi_metadata(ictx, pkg.name)
        meta_cache[key] = meta
    meta = meta_cache[key]
    if not meta or not meta.get("versions"):
        return None
    vs = [v for v, d in meta["versions"].items() if not d.get("yanked") and not d.get("deprecated")]
    return versions.sort_versions(pkg.ecosystem, [v for v in vs if not versions.is_prerelease(pkg.ecosystem, v)])


def choose_fix(ictx: IntelContext, pkg: Package, findings: list[dict], meta_cache: dict) -> dict:
    eco = pkg.ecosystem
    fixable = [f for f in findings if f["advisory"].get("fixed_versions")]
    unfixable = [f for f in findings if not f["advisory"].get("fixed_versions")]
    if not pkg.version:
        return {"state": "insufficient_information", "fix_confidence": "unverified", "target": None,
                "reason": "Installed version is not known exactly (no lockfile/pin)."}
    if not fixable:
        return {"state": "no_verified_fix", "fix_confidence": "unverified", "target": None,
                "reason": "No advisory for this package publishes a fixed version.",
                "unfixed_advisories": [f["advisory"]["id"] for f in unfixable]}
    try:
        mins = [f["advisory"].get("first_fixed") or f["advisory"]["fixed_versions"][0] for f in fixable]
        target = versions.sort_versions(eco, mins)[-1]
    except (versions.VersionError, IndexError):
        return {"state": "insufficient_information", "fix_confidence": "unverified", "target": None,
                "reason": "Fixed versions could not be compared."}
    reg = _registry_versions(ictx, pkg, meta_cache)
    if reg:
        cands = [v for v in reg if versions.compare(eco, v, target) >= 0]
        same_major = [v for v in cands if not versions.is_major_change(eco, pkg.version, v)]
        ordered = same_major + [v for v in cands if v not in same_major]
        cands = ordered[:MAX_CANDIDATES]
        if target not in cands and target in reg:
            cands.insert(0, target)
    else:
        cands = [target]
    check = osv_provider.check_candidate_versions(ictx, eco, pkg.name, cands) if cands else {}
    chosen, conf, remaining = None, "candidate", None
    for v in cands:
        ids = check.get(v)
        if ids == []:
            chosen, conf = v, "verified"
            break
    if chosen is None:
        chosen = target
        ids = check.get(target)
        remaining = ids if ids else None
        conf = "candidate"
    major = versions.is_major_change(eco, pkg.version, chosen)
    evidence = [{"observation": f"Advisories list first fixed version(s): {', '.join(sorted(set(mins)))}; smallest version fixing all: {target}",
                 "source": "OSV affected ranges"}]
    if conf == "verified":
        evidence.append({"observation": f"OSV reports no known advisories for {pkg.name}@{chosen}", "source": "OSV.dev re-query"})
    elif remaining:
        evidence.append({"observation": f"{pkg.name}@{chosen} still has advisories: {', '.join(remaining[:5])}", "source": "OSV.dev re-query"})
    else:
        evidence.append({"observation": f"{pkg.name}@{chosen} could not be re-checked (provider unavailable)", "source": "OSV.dev"})
    if reg is None:
        evidence.append({"observation": "Registry version list unavailable; candidate taken directly from advisory data.",
                         "source": "registry metadata"})
    return {"target": chosen, "minimum_fixed": target, "fix_confidence": conf, "major_change": major,
            "candidates_checked": [{"version": v, "known_advisories": check.get(v)} for v in cands[:MAX_CANDIDATES]],
            "remaining_advisories": remaining, "unfixed_advisories": [f["advisory"]["id"] for f in unfixable],
            "evidence": evidence}


def _meta(ictx: IntelContext, eco: str, name: str, meta_cache: dict) -> Optional[dict]:
    key = (eco, name)
    if key not in meta_cache:
        if len(meta_cache) > 400:
            return None
        meta_cache[key] = npm_metadata(ictx, name)[0] if eco == "npm" else None
    return meta_cache[key]


def _max_satisfying(meta: dict, spec: str) -> Optional[str]:
    """npm resolution picks the highest published (non-prerelease) version satisfying the range."""
    best = None
    for v in (meta.get("versions") or {}):
        if versions.is_prerelease("npm", v):
            continue
        if versions.satisfies("npm", v, spec):
            if best is None or versions.compare("npm", v, best) > 0:
                best = v
    return best


def _walk_path(ictx: IntelContext, d_meta: dict, d_ver: str, hops: list[Package], fix: str, meta_cache: dict):
    """Resolve one path below the direct dependency. Returns (ok, chain, resolved_version_or_None, error)."""
    chain = []
    cur_meta, cur_ver = d_meta, d_ver
    for i, nxt in enumerate(hops):
        spec = ((cur_meta.get("versions") or {}).get(cur_ver, {}).get("dependencies") or {}).get(nxt.name)
        if spec is None:
            chain.append(f"(no longer depends on {nxt.name})")
            return True, chain, None, None
        nmeta = _meta(ictx, "npm", nxt.name, meta_cache)
        if not nmeta:
            return False, chain, None, "registry metadata unavailable"
        nv = _max_satisfying(nmeta, spec)
        if nv is None:
            return False, chain, None, "range unsatisfiable"
        chain.append(f"{nxt.name}@{nv} (range '{spec}')")
        cur_meta, cur_ver = nmeta, nv
    return versions.compare("npm", cur_ver, fix) >= 0, chain, cur_ver, None


def resolve_path_upgrade(ictx: IntelContext, graph: DependencyGraph, paths: list[list[str]], fix: str, meta_cache: dict,
                         max_tries: int = 80) -> Optional[dict]:
    """All `paths` start root -> D -> ... -> pkg with the same direct dependency D. Find the smallest newer
    release of D such that resolving EVERY path with registry dependency ranges (highest satisfying version
    per hop, as npm does) yields pkg >= fix, or drops pkg from the path. npm only; bounded lookups."""
    chains = [[graph.packages[n] for n in p[1:] if n in graph.packages] for p in paths]
    chains = [c for c in chains if len(c) >= 2]
    if not chains or any(p.ecosystem != "npm" for c in chains for p in c):
        return None
    d = chains[0][0]
    dmeta = _meta(ictx, "npm", d.name, meta_cache)
    if not dmeta or not d.version:
        return None
    cands = [v for v in versions.sort_versions("npm", list(dmeta.get("versions", {})))
             if not versions.is_prerelease("npm", v) and versions.compare("npm", v, d.version) > 0][:max_tries]
    for v in cands:
        results = [_walk_path(ictx, dmeta, v, c[1:], fix, meta_cache) for c in chains]
        if any(r[3] == "registry metadata unavailable" for r in results):
            return None
        if all(r[0] for r in results):
            resolved = sorted({r[2] for r in results if r[2]}, key=lambda x: tuple(versions.SemVer.parse(x).key()))
            return {"direct": d.name, "from": d.version, "version": v, "resolved_target": resolved[0] if resolved else None,
                    "resolved_versions": resolved, "dropped": not resolved,
                    "chain": [f"{d.name}@{v}"] + results[0][1], "paths_checked": len(chains),
                    "major_change": versions.is_major_change("npm", d.version, v)}
    return None


def plan_package(ictx: IntelContext, graph: DependencyGraph, pkg: Package, findings: list[dict], src: Optional[RepoSource],
                 meta_cache: dict, reach_level: Optional[str]) -> dict:
    fix = choose_fix(ictx, pkg, findings, meta_cache)
    plan = {"package_id": pkg.id, "package": pkg.name, "ecosystem": pkg.ecosystem, "installed": pkg.version,
            "direct": pkg.direct, "scope": pkg.scope, "findings": [f["id"] for f in findings],
            "advisories": [f["advisory"]["id"] for f in findings], **fix, "actions": [], "compatibility": [],
            "paths": [], "patch": None, "alternatives": []}
    target = fix.get("target")
    paths = graph.paths_to(pkg.id, limit=20)
    plan["paths"] = paths
    if not target:
        if reach_level == "declared_not_imported" and pkg.direct:
            plan["alternatives"].append({"action": "remove", "detail": f"No import of {pkg.name} was found; if unused, remove it."})
        plan["alternatives"].append({"action": "isolate", "detail": "No fixed release: restrict use of the affected functionality, "
                                     "add input validation in front of it, or replace the package after evaluating maintained alternatives."})
        return plan
    state = "safe_candidate" if fix["fix_confidence"] == "verified" and not fix.get("major_change") else "requires_review"
    if fix.get("unfixed_advisories"):
        state = "requires_review"
    manifest_edits: list[dict] = []
    if pkg.direct:
        spec = pkg.declared_spec
        ok = versions.satisfies(pkg.ecosystem, target, spec) if spec else None
        if ok:
            plan["compatibility"].append({"check": "declared range", "result": "pass",
                                          "detail": f"'{spec}' already admits {target}: only the lockfile needs refreshing."})
            plan["actions"].append(_cmd(pkg, target, in_range=True))
        else:
            plan["compatibility"].append({"check": "declared range", "result": "change required" if ok is False else "unknown",
                                          "detail": f"Declared '{spec}' does not admit {target}; the manifest must change."
                                          if ok is False else "Declared range could not be evaluated."})
            plan["actions"].append(_cmd(pkg, target, in_range=False))
            manifest_edits.append({"type": "direct", "name": pkg.name, "new_spec": _new_spec(pkg.ecosystem, spec, target)})
    # ---- transitive: every parent's declared range must admit the fix, else upgrade the direct ancestor
    parents = [graph.packages[p] for p in graph.parents(pkg.id) if p in graph.packages]
    excluded = []
    for par in parents:
        spec = graph.edges.get(par.id, {}).get(pkg.id, {}).get("spec")
        ok = versions.satisfies(pkg.ecosystem, target, spec) if spec else None
        if ok:
            plan["compatibility"].append({"check": f"parent {par.name}@{par.version}", "result": "pass",
                                          "detail": f"{par.name} requires {pkg.name}@'{spec}', which admits {target}."})
        elif ok is False:
            excluded.append(par)
            plan["compatibility"].append({"check": f"parent {par.name}@{par.version}", "result": "excludes fix",
                                          "detail": f"{par.name} requires {pkg.name}@'{spec}', which excludes {target}."})
        else:
            plan["compatibility"].append({"check": f"parent {par.name}@{par.version}", "result": "unknown",
                                          "detail": "Parent's dependency range is not recorded in the lockfile."})
    if not pkg.direct and parents and not excluded and all(
            c["result"] == "pass" for c in plan["compatibility"] if c["check"].startswith("parent")):
        plan["actions"].append({"step": f"Refresh {pkg.name} to {target} within existing ranges",
                                "command": _update_cmd(pkg), "why": "All parents already allow the fixed version."})
    if excluded:
        unresolved_paths = []
        upgrades: dict[str, dict] = {}
        by_direct: dict[str, list] = {}
        for path in paths:
            if len(path) >= 3:  # length-2 paths are root->pkg (direct): handled above
                by_direct.setdefault(path[1], []).append(path)
        for d_id, dpaths in by_direct.items():
            up = resolve_path_upgrade(ictx, graph, dpaths[:10], target, meta_cache)
            if up:
                upgrades[d_id] = up
            else:
                unresolved_paths.extend(dpaths)
        for d_id, up in upgrades.items():
            dpkg = graph.packages[d_id]
            outcome = (f"{pkg.name} is no longer on these paths" if up["dropped"]
                       else f"resolves {pkg.name} to {', '.join(up['resolved_versions'])}")
            plan["compatibility"].append({"check": f"upgrade {dpkg.name} {dpkg.version} -> {up['version']}",
                                          "result": "resolves fix" + (" (major)" if up["major_change"] else ""),
                                          "detail": f"Registry dependency ranges along {up['paths_checked']} path(s), e.g. "
                                                    f"{' -> '.join(up['chain'])}: {outcome}."})
            plan["actions"].append({"step": f"Upgrade {dpkg.name} to {up['version']}", "command": _install_cmd(dpkg, up["version"]),
                                    "why": f"Smallest {dpkg.name} release whose dependency chain {outcome} (registry metadata)."})
            if dpkg.direct:
                manifest_edits.append({"type": "direct", "name": dpkg.name,
                                       "new_spec": _new_spec(dpkg.ecosystem, dpkg.declared_spec, up["version"])})
            if up["major_change"]:
                state = "requires_review"
            if up.get("resolved_target") and up["resolved_target"] != target:
                chk = osv_provider.check_candidate_versions(ictx, pkg.ecosystem, pkg.name, [up["resolved_target"]])
                if chk.get(up["resolved_target"]) != []:
                    state = "requires_review"
                    plan["compatibility"].append({"check": f"{pkg.name}@{up['resolved_target']}", "result": "not verified clean",
                                                  "detail": f"OSV advisories for the resolved version: {chk.get(up['resolved_target']) or 'unavailable'}"})
        plan["resolution_upgrades"] = list(upgrades.values())
        if not pkg.direct and upgrades and not unresolved_paths and state == "requires_review" and fix.get("major_change") \
                and fix["fix_confidence"] == "verified" and not fix.get("unfixed_advisories") \
                and not any(u["major_change"] for u in upgrades.values()) \
                and not any(c["result"] == "not verified clean" for c in plan["compatibility"]):
            # The 0.x/major jump of the transitive package is chosen by its parent's maintainers; the change the
            # application makes is the (non-major) parent upgrade.
            state = "safe_candidate"
            plan["compatibility"].append({"check": "breaking-change boundary", "result": "via parent",
                                          "detail": f"{pkg.name} {pkg.version} -> {target} crosses a semver boundary, but the "
                                                    f"version is selected by the upgraded parent's own declared range."})
        if unresolved_paths and pkg.ecosystem == "npm":
            state = "requires_review"
            manifest_edits.append({"type": "override", "name": pkg.name, "new_spec": target})
            plan["actions"].append({"step": f"Force {pkg.name}@{target} with an npm override",
                                    "command": "npm install  # after adding the override shown in the patch",
                                    "why": "No release of the direct dependency resolves the fix along "
                                           f"{len(unresolved_paths)} path(s). Overrides bypass the parent's declared range, "
                                           "so test the parent's behaviour."})
        elif unresolved_paths:
            state = "requires_review"
            plan["actions"].append({"step": f"Constrain {pkg.name} >= {target}",
                                    "command": f"add a constraint for {pkg.name}>={target}",
                                    "why": "Parent range excludes the fix; no automatic resolution for this ecosystem."})
    if reach_level == "declared_not_imported" and pkg.direct:
        plan["alternatives"].append({"action": "remove", "detail": f"No import of {pkg.name} was found in scanned source; "
                                                                   "removing it eliminates the risk entirely if it is unused."})
    plan["state"] = state
    if src is not None and manifest_edits:
        plan["patch"] = build_patch(src, graph, pkg, manifest_edits)
    return plan


def _new_spec(eco: str, old: Optional[str], target: str) -> str:
    if eco == "npm":
        if old and old.strip().startswith("^"):
            return f"^{target}"
        if old and old.strip().startswith("~"):
            return f"~{target}"
        return target
    if eco == "PyPI":
        return f"=={target}"
    return target


def _install_cmd(pkg: Package, v: str) -> str:
    return {"npm": f"npm install {pkg.name}@{v}", "PyPI": f"pip install '{pkg.name}=={v}'",
            "Go": f"go get {pkg.name}@{v if v.startswith('v') else 'v' + v}", "crates.io": f"cargo update -p {pkg.name} --precise {v}",
            "NuGet": f"dotnet add package {pkg.name} --version {v}", "Maven": f"set {pkg.name} to {v} in pom.xml"}.get(pkg.ecosystem, f"upgrade {pkg.name} to {v}")


def _update_cmd(pkg: Package) -> str:
    return {"npm": f"npm update {pkg.name}", "PyPI": f"pip install --upgrade {pkg.name} (then re-lock)",
            "crates.io": f"cargo update -p {pkg.name}", "Go": f"go get -u {pkg.name}"}.get(pkg.ecosystem, f"refresh lockfile for {pkg.name}")


def _cmd(pkg: Package, v: str, in_range: bool) -> dict:
    if in_range:
        return {"step": f"Update {pkg.name} to {v} (within declared range)", "command": _update_cmd(pkg) if pkg.ecosystem != "npm" else f"npm install {pkg.name}@{v}",
                "why": "The declared range already admits the fixed version."}
    return {"step": f"Upgrade {pkg.name} {pkg.version} -> {v}", "command": _install_cmd(pkg, v),
            "why": "The declared version/range excludes the fixed version."}


# --------------------------------------------------------------------------- patches

def build_patch(src: RepoSource, graph: DependencyGraph, pkg: Package, edits: list[dict]) -> Optional[dict]:
    """Return {"file", "diff", "note"}; the repository is never modified."""
    if pkg.ecosystem == "npm":
        manifest = _manifest_for(graph, pkg, "package.json")
        if not manifest or not src.exists(manifest):
            return None
        original = src.read_text(manifest) or ""
        try:
            data = json.loads(original)
        except json.JSONDecodeError:
            return None
        for e in edits:
            if e["type"] == "direct":
                for field in ("dependencies", "devDependencies", "optionalDependencies"):
                    if isinstance(data.get(field), dict) and e["name"] in data[field]:
                        data[field][e["name"]] = e["new_spec"]
            elif e["type"] == "override":
                data.setdefault("overrides", {})[e["name"]] = e["new_spec"]
        indent = 2 if "\n  \"" in original else 4 if "\n    \"" in original else 2
        updated = json.dumps(data, indent=indent, ensure_ascii=False) + ("\n" if original.endswith("\n") else "")
        return _diff(manifest, original, updated,
                     "Manifest change only. Run the package manager to regenerate the lockfile, then rescan to confirm.")
    if pkg.ecosystem == "PyPI":
        files = [f for f in pkg.source_file.split(", ") if f.endswith(".txt")]
        if not files:
            return None
        manifest = files[0]
        original = src.read_text(manifest) or ""
        lines = original.splitlines(keepends=True)
        changed = False
        for e in edits:
            rx = re.compile(rf"^(\s*{re.escape(e['name'])}(?:\[[^\]]*\])?\s*)(==|>=|~=|<=|!=|>|<)?[^;#\s\\]*", re.I)
            for i, line in enumerate(lines):
                norm = re.sub(r"[-_.]+", "-", line.split("==")[0].split(">=")[0].strip().lower())
                if norm == e["name"] or norm.startswith(e["name"] + "["):
                    lines[i] = rx.sub(lambda m: f"{m.group(1).rstrip()}{e['new_spec']}", line, count=1)
                    changed = True
        if not changed:
            return None
        return _diff(manifest, original, "".join(lines),
                     "If this file is generated (pip-compile), regenerate it from its .in source instead.")
    return None


def _manifest_for(graph: DependencyGraph, pkg: Package, fname: str) -> Optional[str]:
    for path in graph.paths_to(pkg.id, limit=5):
        root = graph.roots.get(path[0])
        if root and root.manifest.endswith(fname):
            return root.manifest
    for root in graph.roots.values():
        if root.manifest.endswith(fname) and root.ecosystem == pkg.ecosystem:
            return root.manifest
    return None


def _diff(path: str, a: str, b: str, note: str) -> Optional[dict]:
    if a == b:
        return None
    diff = "".join(difflib.unified_diff(a.splitlines(keepends=True), b.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}", n=2))
    return {"file": path, "diff": diff, "note": note, "applied": False}


def simulation_changes(plans: list[dict], pkg_index: dict) -> dict:
    """Package versions the combined remediation is expected to produce (input for what-if).

    direct packages -> the highest version any plan requires for them;
    transitive packages fixed via a parent upgrade -> the version that parent's range resolves to;
    transitive packages fixed via override -> the override target.
    """
    out: dict[str, str] = {}

    def bump(pid, eco, ver):
        if not ver or pid not in pkg_index:
            return
        try:
            if pid not in out or versions.compare(eco, ver, out[pid]) > 0:
                out[pid] = ver
        except versions.VersionError:
            out.setdefault(pid, ver)
    by_name = {}
    for pid, p in pkg_index.items():
        if p["direct"]:
            by_name[(p["ecosystem"], p["name"])] = pid
    for pl in plans:
        if not pl.get("target"):
            continue
        if pl["direct"]:
            bump(pl["package_id"], pl["ecosystem"], pl["target"])
        for up in pl.get("resolution_upgrades") or []:
            dpid = by_name.get((pl["ecosystem"], up["direct"]))
            if dpid:
                bump(dpid, pl["ecosystem"], up["version"])
            if up.get("resolved_versions"):
                bump(pl["package_id"], pl["ecosystem"], up["resolved_versions"][-1])
        if any("override" in a["step"] for a in pl.get("actions", [])):
            bump(pl["package_id"], pl["ecosystem"], pl["target"])
    return out


def combined_patch(plans: list[dict], src: Optional[RepoSource], graph: DependencyGraph) -> Optional[dict]:
    """One patch per manifest combining every plan's edits (for the remediation report)."""
    if src is None:
        return None
    edits_by_pkg: dict[str, list] = {}
    for p in plans:
        if not p.get("patch"):
            continue
        pkg = graph.packages.get(p["package_id"])
        if not pkg:
            continue
        man = p["patch"]["file"]
        edits_by_pkg.setdefault(man, []).append((pkg, p))
    out = []
    for man, items in edits_by_pkg.items():
        pkg0 = items[0][0]
        # (type, name) -> (ecosystem, declared_spec, version); keep the HIGHEST version any plan requires
        wanted: dict[tuple, tuple] = {}

        def want(kind, p: Package, ver: str):
            key = (kind, p.name)
            cur = wanted.get(key)
            try:
                if cur is None or versions.compare(p.ecosystem, ver, cur[2]) > 0:
                    wanted[key] = (p.ecosystem, p.declared_spec, ver)
            except versions.VersionError:
                wanted.setdefault(key, (p.ecosystem, p.declared_spec, ver))
        for pkg, p in items:
            if pkg.direct and p.get("target"):
                want("direct", pkg, p["target"])
            for up in p.get("resolution_upgrades") or []:
                par = next((x for x in graph.packages.values() if x.name == up["direct"] and x.direct), None)
                if par:
                    want("direct", par, up["version"])
            if any("override" in a["step"] for a in p.get("actions", [])):
                want("override", pkg, p["target"])
        edits = [{"type": k[0], "name": k[1], "new_spec": v[2] if k[0] == "override" else _new_spec(v[0], v[1], v[2])}
                 for k, v in wanted.items()]
        patch = build_patch(src, graph, pkg0, edits)
        if patch:
            patch["changes"] = [{"type": k[0], "package": k[1], "to": v[2]} for k, v in wanted.items()]
        if patch:
            out.append(patch)
    return {"files": out} if out else None
