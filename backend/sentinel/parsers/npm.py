"""npm ecosystem: package.json, package-lock.json (v1/v2/v3), npm-shrinkwrap.json,
yarn.lock (classic v1 and berry), pnpm-lock.yaml (v5/v6/v9)."""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

import yaml

from .. import versions
from ..models import Package
from ..reposource import RepoSource, dirname
from .base import ManifestError, ParseContext, ParseOutcome, load_json, make_root, safe_name, safe_version

DEP_FIELDS = (("dependencies", "runtime"), ("devDependencies", "dev"),
              ("optionalDependencies", "optional"), ("peerDependencies", "peer"))
DEFAULT_REGISTRY_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}


def classify_spec(spec: str) -> str:
    s = (spec or "").strip()
    if s.startswith(("file:", "link:")):
        return "file"
    if s.startswith("workspace:"):
        return "workspace"
    if s.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:")) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
        return "git"
    if s.startswith(("http://", "https://")):
        return "url"
    return "registry"


def source_type_from_resolved(resolved: Optional[str], spec: Optional[str] = None) -> str:
    if resolved:
        r = resolved
        if r.startswith(("git+", "git:", "github:")) or "codeload.github.com" in r:
            return "git"
        if r.startswith(("file:",)) or not re.match(r"^[a-z+]+:", r):
            return "file"
        if r.startswith(("http://", "https://")):
            return "registry" if r.endswith(".tgz") and "/-/" in r else "url"
    if spec:
        return classify_spec(spec)
    return "registry"


# --------------------------------------------------------------------------- package.json

def parse_package_json(src: RepoSource, path: str, ctx: ParseContext, has_lock: bool) -> dict:
    data = load_json(src.read_text(path) or "", path)
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: expected a JSON object")
    declared: dict[str, tuple[str, str]] = {}
    for field_name, scope in DEP_FIELDS:
        deps = data.get(field_name) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in list(deps.items())[:5000]:
            n = safe_name(name)
            if not n or not isinstance(spec, str):
                continue
            if n not in declared or scope == "runtime":
                declared[n] = (spec[:256], scope)
    meta = {
        "name": data.get("name") if isinstance(data.get("name"), str) else None,
        "declared": declared,
        "scripts": {k: v for k, v in (data.get("scripts") or {}).items()
                    if isinstance(k, str) and isinstance(v, str)} if isinstance(data.get("scripts"), dict) else {},
        "overrides": data.get("overrides") if isinstance(data.get("overrides"), dict) else None,
        "publishConfig": data.get("publishConfig") if isinstance(data.get("publishConfig"), dict) else None,
    }
    for n, (spec, scope) in declared.items():
        kind = classify_spec(spec)
        if kind == "git" and not re.search(r"#[0-9a-f]{40}$", spec):
            ctx.unpinned.append({"file": path, "name": n, "spec": spec, "ecosystem": "npm",
                                 "reason": "git dependency without an immutable commit SHA"})
        elif kind == "url":
            ctx.unpinned.append({"file": path, "name": n, "spec": spec, "ecosystem": "npm",
                                 "reason": "remote tarball URL dependency (contents can change)"})
        elif kind == "registry" and spec.strip() in ("*", "latest", "", "x"):
            ctx.unpinned.append({"file": path, "name": n, "spec": spec, "ecosystem": "npm",
                                 "reason": "wildcard / 'latest' version"})
        elif kind == "registry" and not has_lock and not versions.is_exact_spec("npm", spec):
            ctx.unpinned.append({"file": path, "name": n, "spec": spec, "ecosystem": "npm",
                                 "reason": "version range without a lockfile (resolution is not reproducible)"})
    return meta


def add_manifest_only(ctx: ParseContext, path: str, meta: dict) -> int:
    """No lockfile: record direct deps. Exact pins get a version; ranges stay unresolved."""
    d = dirname(path)
    root = make_root(ctx, "npm", d, meta.get("name") or d or "app", path)
    ctx.declared[root.id] = {n: s for n, (s, _) in meta["declared"].items()}
    count = 0
    for name, (spec, scope) in meta["declared"].items():
        kind = classify_spec(spec)
        exact = versions.is_exact_spec("npm", spec) and kind == "registry"
        pkg = Package(ecosystem="npm", name=name, version=spec.lstrip("=").strip() if exact else None,
                      source_file=path, declared_spec=spec, version_exact=exact, direct=True, scope=scope,
                      source_type=kind)
        if kind == "file":
            pkg.local_path = _join(d, spec.split(":", 1)[1])
        p = ctx.graph.add_package(pkg)
        ctx.graph.add_edge(root.id, p.id, "direct", spec, scope)
        count += 1
    return count


def _join(base: str, rel: str) -> Optional[str]:
    parts = [p for p in (base.split("/") if base else [])] + [p for p in rel.replace("\\", "/").split("/")]
    out = []
    for p in parts:
        if p in ("", "."):
            continue
        if p == "..":
            if not out:
                return None  # escapes repository root
            out.pop()
        else:
            out.append(p)
    return "/".join(out)


# --------------------------------------------------------------------------- package-lock.json

def parse_package_lock(src: RepoSource, path: str, ctx: ParseContext, meta: Optional[dict]) -> ParseOutcome:
    data = load_json(src.read_text(path) or "", path)
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: expected a JSON object")
    lv = data.get("lockfileVersion", 1)
    d = dirname(path)
    root = make_root(ctx, "npm", d, (meta or {}).get("name") or data.get("name") or d or "app",
                     manifest=_sibling(d, "package.json") if meta else path, lockfile=path)
    declared = (meta or {}).get("declared", {})
    ctx.declared[root.id] = {n: s for n, (s, _) in declared.items()}
    if isinstance(data.get("packages"), dict) and lv in (2, 3):
        n = _parse_lock_v2(data["packages"], path, d, root.id, ctx, declared)
    elif isinstance(data.get("dependencies"), dict):
        n = _parse_lock_v1(data["dependencies"], path, root.id, ctx, declared)
        lv = 1
    else:
        raise ManifestError(f"{path}: unrecognised lockfile structure")
    ctx.declared[root.id] = {n: s for n, (s, _) in declared.items()}
    _check_drift(ctx, path, root.id, declared)
    return ParseOutcome(path, "npm", "lockfile", f"package-lock v{lv}", "parsed", n,
                        "Exact versions, integrity hashes and dependency edges parsed from lockfile.")


def _sibling(d: str, name: str) -> str:
    return f"{d}/{name}" if d else name


def _scope_of(entry: dict) -> str:
    if entry.get("dev") or entry.get("devOptional"):
        return "dev"
    if entry.get("optional"):
        return "optional"
    if entry.get("peer"):
        return "peer"
    return "runtime"


def _parse_lock_v2(pkgs: dict, path: str, base_dir: str, root_id: str, ctx: ParseContext, declared: dict) -> int:
    loc_to_id: dict[str, str] = {}
    entries: dict[str, dict] = {}
    for loc, entry in pkgs.items():
        if loc == "" or not isinstance(entry, dict) or not isinstance(loc, str):
            continue
        entries[loc] = entry
    if len(entries) > 20000:
        raise ManifestError(f"{path}: dependency graph exceeds size limit")

    def name_of(loc: str, entry: dict) -> Optional[str]:
        if "node_modules/" in loc:
            return safe_name(loc.rsplit("node_modules/", 1)[1])
        return safe_name(entry.get("name") or loc.rsplit("/", 1)[-1])

    # First pass: create package nodes (links are resolved to their targets)
    for loc, entry in entries.items():
        if entry.get("link"):
            continue
        name = name_of(loc, entry)
        if not name:
            continue
        version = safe_version(entry.get("version"))
        resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else None
        is_local = "node_modules/" not in loc  # workspace / file: target
        pkg = Package(
            ecosystem="npm", name=name, version=version, source_file=path, version_exact=bool(version),
            scope=_scope_of(entry), integrity=entry.get("integrity") if isinstance(entry.get("integrity"), str) else None,
            resolved=resolved[:512] if resolved else None,
            source_type="file" if is_local else source_type_from_resolved(resolved),
            has_install_script=bool(entry.get("hasInstallScript")),
            local_path=_join(base_dir, loc) if is_local else None,
            license=entry.get("license") if isinstance(entry.get("license"), str) else None,
        )
        p = ctx.graph.add_package(pkg)
        loc_to_id[loc] = p.id
    # links: node_modules/x -> target location
    for loc, entry in entries.items():
        if entry.get("link") and isinstance(entry.get("resolved"), str):
            target = entry["resolved"]
            if target in loc_to_id:
                loc_to_id[loc] = loc_to_id[target]

    def resolve(from_loc: str, dep: str) -> Optional[str]:
        cur = from_loc
        while True:
            cand = f"{cur}/node_modules/{dep}" if cur else f"node_modules/{dep}"
            if cand in loc_to_id:
                return loc_to_id[cand]
            if not cur:
                return None
            if "/node_modules/" in cur:
                cur = cur.rsplit("/node_modules/", 1)[0]
            elif cur.startswith("node_modules/"):
                cur = ""
            else:
                cur = ""  # workspace dirs resolve from root

    # Root declarations: package.json when present, otherwise the lockfile's own root entry packages[""].
    root_decl: dict[str, tuple[str, str]] = dict(declared)
    root_entry = pkgs.get("") if isinstance(pkgs.get(""), dict) else {}
    for field_name, scope in DEP_FIELDS:
        for dep, spec in (root_entry.get(field_name) or {}).items():
            if safe_name(dep) and isinstance(spec, str) and dep not in root_decl:
                root_decl[dep] = (spec[:256], scope)
    if not declared:
        declared.update(root_decl)
    count = 0
    for loc, entry in entries.items():
        if entry.get("link"):
            continue
        src_id = loc_to_id.get(loc)
        if not src_id:
            continue
        count += 1
        for field_name, scope in DEP_FIELDS:
            deps = entry.get(field_name) or {}
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                tgt = resolve(loc, dep)
                if tgt:
                    ctx.graph.add_edge(src_id, tgt, "depends", spec if isinstance(spec, str) else None, scope)
    return _attach_root(ctx, root_id, root_decl, lambda dep: resolve("", dep), path) or count


def _attach_root(ctx, root_id, declared, resolver, path) -> int:
    for dep, (spec, scope) in declared.items():
        tgt = resolver(dep)
        if tgt:
            pkg = ctx.graph.packages[tgt]
            pkg.direct = True
            pkg.declared_spec = spec
            if scope == "runtime":
                pkg.scope = "runtime"
            ctx.graph.add_edge(root_id, tgt, "direct", spec, scope)
        else:
            ctx.drift.append({"file": path, "name": dep, "declared": spec, "locked": None, "ecosystem": "npm",
                              "issue": "declared in manifest but missing from lockfile"})
    return len([p for p in ctx.graph.packages.values() if path in p.source_file])


def _parse_lock_v1(deps: dict, path: str, root_id: str, ctx: ParseContext, declared: dict) -> int:
    # Each scope is (dict of name -> entry, parent scope). Resolve requires by walking up.
    count = 0
    budget = [20000]

    def walk(level: dict, chain: list[dict]):
        nonlocal count
        ids = {}
        for name, entry in level.items():
            n = safe_name(name)
            if not n or not isinstance(entry, dict):
                continue
            budget[0] -= 1
            if budget[0] < 0:
                raise ManifestError(f"{path}: dependency graph exceeds size limit")
            version = safe_version(entry.get("version"))
            resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else None
            st = "file" if version and version.startswith("file:") else source_type_from_resolved(resolved, version)
            if st != "registry" and version and not versions.is_valid("npm", version):
                resolved, version = resolved or version, None
            pkg = Package(ecosystem="npm", name=n, version=version, source_file=path, version_exact=bool(version),
                          scope=_scope_of(entry), integrity=entry.get("integrity") if isinstance(entry.get("integrity"), str) else None,
                          resolved=resolved[:512] if resolved else None, source_type=st)
            p = ctx.graph.add_package(pkg)
            ids[n] = p.id
            count += 1
        scope_map = {"ids": ids}
        new_chain = chain + [scope_map]
        for name, entry in level.items():
            if not isinstance(entry, dict) or name not in ids:
                continue
            nested = entry.get("dependencies")
            child_chain = new_chain
            if isinstance(nested, dict):
                child_ids = walk(nested, new_chain)
                child_chain = new_chain + [{"ids": child_ids}]
            for req, spec in (entry.get("requires") or {}).items():
                tgt = None
                for sc in reversed(child_chain):
                    if req in sc["ids"]:
                        tgt = sc["ids"][req]
                        break
                if tgt:
                    ctx.graph.add_edge(ids[name], tgt, "depends", spec if isinstance(spec, str) else None)
        return ids

    top = walk(deps, [])
    if declared:
        _attach_root(ctx, root_id, declared, lambda dep: top.get(dep), path)
    else:
        # No package.json: v1 lockfiles hoist transitive deps to the top level, so only
        # top-level packages that nothing else requires are treated as direct.
        for name, pid in top.items():
            if not ctx.graph.redges.get(pid):
                ctx.graph.packages[pid].direct = True
                ctx.graph.add_edge(root_id, pid, "direct")
    return count


def _check_drift(ctx: ParseContext, path: str, root_id: str, declared: dict):
    for dep, (spec, _scope) in declared.items():
        for tgt in ctx.graph.edges.get(root_id, {}):
            pkg = ctx.graph.packages.get(tgt)
            if pkg and pkg.name == dep and pkg.version and classify_spec(spec) == "registry":
                ok = versions.satisfies("npm", pkg.version, spec)
                if ok is False:
                    ctx.drift.append({"file": path, "name": dep, "declared": spec, "locked": pkg.version,
                                      "ecosystem": "npm", "issue": "locked version does not satisfy the declared range"})


# --------------------------------------------------------------------------- yarn.lock

def parse_yarn_lock(src: RepoSource, path: str, ctx: ParseContext, meta: Optional[dict]) -> ParseOutcome:
    text = src.read_text(path) or ""
    d = dirname(path)
    root = make_root(ctx, "npm", d, (meta or {}).get("name") or d or "app",
                     manifest=_sibling(d, "package.json") if meta else path, lockfile=path)
    declared = (meta or {}).get("declared", {})
    ctx.declared[root.id] = {n: s for n, (s, _) in declared.items()}
    if "__metadata:" in text[:2000]:
        entries = _yarn_berry(text, path)
        parser = "yarn.lock (berry)"
    else:
        entries = _yarn_classic(text, path)
        parser = "yarn.lock (v1)"
    spec_to_id: dict[str, str] = {}
    for e in entries:
        name = e["name"]
        pkg = Package(ecosystem="npm", name=name, version=e.get("version"), source_file=path,
                      version_exact=bool(e.get("version")), integrity=e.get("integrity"),
                      resolved=e.get("resolved"), source_type=source_type_from_resolved(e.get("resolved")),
                      scope="unknown")
        p = ctx.graph.add_package(pkg)
        for s in e["specs"]:
            spec_to_id[s] = p.id
        e["id"] = p.id
    for e in entries:
        for dep, spec in e.get("deps", {}).items():
            tgt = spec_to_id.get(f"{dep}@{spec}") or spec_to_id.get(f"{dep}@npm:{spec}")
            if tgt:
                ctx.graph.add_edge(e["id"], tgt, "depends", spec)

    def resolver(dep):
        spec = declared.get(dep, ("", ""))[0]
        return spec_to_id.get(f"{dep}@{spec}") or spec_to_id.get(f"{dep}@npm:{spec}")
    _attach_root(ctx, root.id, declared, resolver, path)
    # yarn.lock does not mark dev/optional: infer from root declarations only
    _propagate_scopes(ctx, root.id)
    _check_drift(ctx, path, root.id, declared)
    return ParseOutcome(path, "npm", "lockfile", parser, "parsed", len(entries),
                        "Exact versions and edges parsed.",
                        ["Dev/runtime classification inferred from package.json (yarn.lock does not record it)."])


def _yarn_classic(text: str, path: str) -> list[dict]:
    entries = []
    cur = None
    section = None
    for raw in text.splitlines()[:400000]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            specs = [s.strip().strip('"') for s in line[:-1].split(",")]
            name = _spec_name(specs[0])
            if not name:
                cur = None
                continue
            cur = {"name": name, "specs": specs, "deps": {}}
            entries.append(cur)
            section = None
        elif cur is not None and indent == 2:
            section = None
            if line.endswith(":"):
                section = line[:-1]
                continue
            key, _, val = line.partition(" ")
            val = val.strip().strip('"')
            if key == "version":
                cur["version"] = safe_version(val)
            elif key == "resolved":
                cur["resolved"] = val[:512]
            elif key == "integrity":
                cur["integrity"] = val[:256]
        elif cur is not None and indent >= 4 and section in ("dependencies", "optionalDependencies"):
            key, _, val = line.partition(" ")
            k = key.strip('"')
            if safe_name(k):
                cur["deps"][k] = val.strip().strip('"')
    if len(entries) > 20000:
        raise ManifestError(f"{path}: dependency graph exceeds size limit")
    return entries


def _yarn_berry(text: str, path: str) -> list[dict]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestError(f"{path}: invalid YAML") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: unexpected structure")
    entries = []
    for key, val in data.items():
        if key == "__metadata" or not isinstance(val, dict):
            continue
        specs = [s.strip() for s in str(key).split(",")]
        name = _spec_name(specs[0])
        if not name:
            continue
        res = str(val.get("resolution", ""))
        if "@workspace:" in res or "@link:" in res or "@file:" in res:
            continue
        deps = {k: str(v) for k, v in (val.get("dependencies") or {}).items()} if isinstance(val.get("dependencies"), dict) else {}
        entries.append({"name": name, "specs": specs, "version": safe_version(str(val.get("version", ""))),
                        "integrity": f"yarn-checksum:{val['checksum']}" if val.get("checksum") else None,
                        "resolved": res[:512] or None, "deps": deps})
    return entries


def _spec_name(spec: str) -> Optional[str]:
    if spec.startswith("@"):
        idx = spec.find("@", 1)
    else:
        idx = spec.find("@")
    name = spec[:idx] if idx > 0 else spec
    return safe_name(name)


def _propagate_scopes(ctx: ParseContext, root_id: str):
    """Mark packages reachable only through dev roots as dev; others runtime."""
    runtime, dev = set(), set()
    for tgt, attrs in ctx.graph.edges.get(root_id, {}).items():
        (dev if attrs.get("scope") == "dev" else runtime).add(tgt)

    def closure(start):
        seen, stack = set(start), list(start)
        while stack:
            n = stack.pop()
            for m in ctx.graph.edges.get(n, {}):
                if m not in seen:
                    seen.add(m)
                    stack.append(m)
        return seen
    rt = closure(runtime)
    dv = closure(dev)
    for pid in rt | dv:
        p = ctx.graph.packages.get(pid)
        if p and p.scope == "unknown":
            p.scope = "runtime" if pid in rt else "dev"


# --------------------------------------------------------------------------- pnpm-lock.yaml

def _pnpm_key(key: str) -> tuple[Optional[str], Optional[str]]:
    k = key.lstrip("/")
    k = re.sub(r"\(.*\)$", "", k)           # v6/v9 peer suffix
    if "@" in k[1:]:
        idx = k.rfind("@")
        if idx > 0:
            name, ver = k[:idx], k[idx + 1:]
            ver = ver.split("_", 1)[0]
            return safe_name(name), safe_version(ver)
    # v5: /name/1.2.3 or /@scope/name/1.2.3
    parts = k.split("/")
    if len(parts) >= 2:
        return safe_name("/".join(parts[:-1])), safe_version(parts[-1].split("_", 1)[0])
    return None, None


def _pnpm_ver(v) -> Optional[str]:
    if isinstance(v, dict):
        v = v.get("version")
    if not isinstance(v, str):
        return None
    v = re.sub(r"\(.*\)$", "", v).split("_", 1)[0]
    if v.startswith(("link:", "file:")):
        return None
    return v


def parse_pnpm_lock(src: RepoSource, path: str, ctx: ParseContext, meta: Optional[dict]) -> ParseOutcome:
    try:
        data = yaml.safe_load(src.read_text(path) or "")
    except yaml.YAMLError as exc:
        raise ManifestError(f"{path}: invalid YAML") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: unexpected structure")
    d = dirname(path)
    lv = str(data.get("lockfileVersion", ""))
    root = make_root(ctx, "npm", d, (meta or {}).get("name") or d or "app",
                     manifest=_sibling(d, "package.json") if meta else path, lockfile=path)
    declared = (meta or {}).get("declared", {})
    ctx.declared[root.id] = {n: s for n, (s, _) in declared.items()}
    pkgs = data.get("packages") or {}
    snaps = data.get("snapshots") or {}
    key_to_id: dict[tuple, str] = {}
    for key, val in (pkgs.items() if isinstance(pkgs, dict) else []):
        name, ver = _pnpm_key(str(key))
        if not name or not ver:
            continue
        val = val if isinstance(val, dict) else {}
        res = val.get("resolution") or {}
        pkg = Package(ecosystem="npm", name=name, version=ver, source_file=path, version_exact=True,
                      integrity=res.get("integrity") if isinstance(res, dict) else None,
                      resolved=(res.get("tarball") if isinstance(res, dict) else None),
                      source_type="git" if isinstance(res, dict) and res.get("type") == "git" else "registry",
                      scope="dev" if val.get("dev") is True else ("optional" if val.get("optional") else "runtime"),
                      has_install_script=bool(val.get("requiresBuild")) if "requiresBuild" in val else None)
        p = ctx.graph.add_package(pkg)
        key_to_id[(name, ver)] = p.id
    edge_src = snaps if isinstance(snaps, dict) and snaps else pkgs
    for key, val in (edge_src.items() if isinstance(edge_src, dict) else []):
        name, ver = _pnpm_key(str(key))
        sid = key_to_id.get((name, ver))
        if not sid or not isinstance(val, dict):
            continue
        for fld in ("dependencies", "optionalDependencies"):
            for dep, dv in (val.get(fld) or {}).items():
                tv = _pnpm_ver(dv)
                if tv and (dep, tv) in key_to_id:
                    ctx.graph.add_edge(sid, key_to_id[(dep, tv)], "depends")
    importers = data.get("importers") or {".": {k: data.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")}}
    imp = importers.get(".") or {}
    found = {}
    for fld, scope in (("dependencies", "runtime"), ("devDependencies", "dev"), ("optionalDependencies", "optional")):
        for dep, dv in (imp.get(fld) or {}).items():
            tv = _pnpm_ver(dv)
            if tv and (dep, tv) in key_to_id:
                found[dep] = key_to_id[(dep, tv)]
                if dep not in declared:
                    spec = dv.get("specifier") if isinstance(dv, dict) else None
                    declared[dep] = (spec or tv, scope)
    _attach_root(ctx, root.id, declared, lambda dep: found.get(dep), path)
    _check_drift(ctx, path, root.id, declared)
    lim = []
    if len(importers) > 1:
        lim.append("Only the root importer ('.') is attached as an application component; other workspace importers are listed as packages.")
    return ParseOutcome(path, "npm", "lockfile", f"pnpm-lock v{lv or '?'}", "parsed", len(key_to_id),
                        "Exact versions and edges parsed.", lim)


def parse_npmrc(src: RepoSource, path: str, ctx: ParseContext):
    text = src.read_text(path, 64 * 1024) or ""
    for line in text.splitlines()[:500]:
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.match(r"^(@[\w.-]+:)?registry\s*=\s*(\S+)$", line)
        if m:
            url = m.group(2)
            host = urlparse(url).hostname or url
            ctx.registries.append({"file": path, "scope": (m.group(1) or "").rstrip(":") or None,
                                   "url": f"{urlparse(url).scheme}://{host}" if urlparse(url).scheme else host,
                                   "kind": "npm"})
        if re.search(r"_authToken\s*=", line) and "${" not in line:
            ctx.registries.append({"file": path, "scope": None, "url": None, "kind": "npm-token-literal"})
