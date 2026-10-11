"""PyPI ecosystem: requirements*.txt / constraints, pyproject.toml (PEP 621 + Poetry),
poetry.lock, Pipfile.lock."""
from __future__ import annotations

import re
import tomllib
from typing import Optional
from urllib.parse import urlparse

from packaging.requirements import InvalidRequirement, Requirement

from .. import versions
from ..models import Package
from ..reposource import RepoSource, dirname
from .base import ManifestError, ParseContext, ParseOutcome, load_json, make_root, norm_pypi, safe_version

MAX_INCLUDE_DEPTH = 5


def _exact_from_specifier(spec: str) -> Optional[str]:
    m = re.match(r"^\s*===?\s*([A-Za-z0-9.+!_-]+)\s*$", spec or "")
    if m and "*" not in m.group(1):
        return m.group(1)
    return None


def parse_requirements(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    d = dirname(path)
    is_constraints = "constraint" in path.rsplit("/", 1)[-1].lower()
    root = make_root(ctx, "PyPI", d, d or "python-app", path, sub=path.rsplit("/", 1)[-1])
    entries: list[dict] = []
    limitations: list[str] = []
    seen_files: set[str] = set()
    _read_req_file(src, path, ctx, entries, limitations, seen_files, 0)
    via_present = any(e["via"] for e in entries)
    by_name: dict[str, str] = {}
    declared: dict[str, str] = {}
    for e in entries:
        pkg = Package(ecosystem="PyPI", name=e["name"], version=e["version"], source_file=e["file"],
                      declared_spec=e["spec"] or None, version_exact=e["version"] is not None,
                      direct=True, scope="runtime" if not is_constraints else "unknown",
                      integrity=e["hash"], source_type=e["source_type"], resolved=e.get("url"))
        if via_present and e["via"] and not any(v.startswith("-r") or v.startswith("-c") for v in e["via"]):
            pkg.direct = False
        p = ctx.graph.add_package(pkg)
        by_name[e["name"]] = p.id
        if pkg.direct:
            declared[e["name"]] = e["spec"]
    ctx.declared[root.id] = declared
    for e in entries:
        pid = by_name[e["name"]]
        parents = [norm_pypi(v) for v in e["via"] if not v.startswith("-")]
        if via_present and parents:
            for par in parents:
                if par in by_name:
                    ctx.graph.add_edge(by_name[par], pid, "depends")
            if any(v.startswith("-r") for v in e["via"]):
                ctx.graph.add_edge(root.id, pid, "direct", e["spec"])
        else:
            relation = "direct" if not via_present else "unknown-path"
            ctx.graph.add_edge(root.id, pid, relation, e["spec"])
    if not via_present:
        limitations.append("requirements.txt does not record which package pulled in which; transitive "
                           "relationships are unknown (pip-compile '# via' annotations are used when present).")
    status = "parsed" if all(e["version"] for e in entries) else "partial"
    if status == "partial":
        limitations.append("Some requirements are ranges, not exact pins; their installed version cannot be verified.")
    return ParseOutcome(path, "PyPI", "manifest", "requirements.txt" + (" (pip-compile annotations)" if via_present else ""),
                        status, len(entries), f"{len(entries)} requirement(s) parsed.", limitations)


def _read_req_file(src, path, ctx, entries, limitations, seen, depth):
    if path in seen or depth > MAX_INCLUDE_DEPTH:
        return
    seen.add(path)
    text = src.read_text(path, 2 * 1024 * 1024)
    if text is None:
        limitations.append(f"Included file not found or unreadable: {path}")
        return
    d = dirname(path)
    # join continuation lines but keep "# via" comment lines for pip-compile output
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines()[:50000]:
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append(buf + raw)
        buf = ""
    if buf:
        logical.append(buf)
    last = None
    in_via = False
    for line in logical:
        stripped = line.strip()
        if stripped.startswith("#"):
            body = stripped.lstrip("#").strip()
            if last is not None and body.startswith("via"):
                rest = body[3:].strip()
                if rest:
                    last["via"].append(rest)
                in_via = True
            elif last is not None and in_via and body:
                last["via"].append(body)
            continue
        in_via = False
        line = re.sub(r"\s+#.*$", "", stripped)
        if not line:
            continue
        if line.startswith(("-r ", "--requirement")) or line.startswith(("-c ", "--constraint")):
            target = line.split(None, 1)[1].strip() if " " in line else line.split("=", 1)[-1]
            inc = _join(d, target)
            if inc:
                _read_req_file(src, inc, ctx, entries, limitations, seen, depth + 1)
            last = None
            continue
        if line.startswith(("--index-url", "-i ", "--extra-index-url")):
            url = re.split(r"[=\s]", line, 1)[1].strip() if re.search(r"[=\s]", line) else ""
            kind = "pip-extra-index" if line.startswith("--extra-index-url") else "pip-index"
            parsed = urlparse(url)
            ctx.registries.append({"file": path, "scope": None, "kind": kind,
                                   "url": f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else url[:80],
                                   "insecure": parsed.scheme == "http",
                                   "has_credentials": bool(parsed.username or parsed.password)})
            continue
        if line.startswith("-"):
            if line.startswith(("-e ", "--editable")):
                url = line.split(None, 1)[1] if " " in line else ""
                _add_url_req(path, url, entries, ctx)
            continue
        hashes = re.findall(r"--hash[=\s]+(\S+)", line)
        req_text = re.sub(r"\s--hash[=\s]+\S+", "", line).strip()
        if re.match(r"^(git\+|hg\+|svn\+|bzr\+|https?://)", req_text) or " @ " in req_text:
            _add_url_req(path, req_text, entries, ctx)
            last = entries[-1] if entries else None
            continue
        try:
            req = Requirement(req_text)
        except InvalidRequirement:
            limitations.append(f"Unparsable requirement line skipped in {path}")
            continue
        spec = str(req.specifier)
        exact = _exact_from_specifier(spec)
        e = {"name": norm_pypi(req.name), "spec": spec, "version": exact, "file": path,
             "hash": hashes[0] if hashes else None, "source_type": "registry", "via": []}
        if not exact:
            ctx.unpinned.append({"file": path, "name": e["name"], "spec": spec or "(any)", "ecosystem": "PyPI",
                                 "reason": "not pinned to an exact version" if spec else "no version constraint"})
        entries.append(e)
        last = e


def _add_url_req(path, text, entries, ctx):
    m = re.search(r"#egg=([A-Za-z0-9._-]+)", text) or re.match(r"^([A-Za-z0-9._-]+)\s*@", text)
    name = norm_pypi(m.group(1)) if m else "unknown-url-requirement"
    ref_m = re.search(r"@([0-9a-fA-F]{40})\b", text)
    url = text.split("@", 1)[1].strip() if " @ " in text else text
    parsed = urlparse(url.replace("git+", ""))
    st = "git" if "git+" in text or parsed.path.endswith(".git") else "url"
    if not ref_m:
        ctx.unpinned.append({"file": path, "name": name, "spec": f"{parsed.scheme}://{parsed.hostname or ''}/...",
                             "ecosystem": "PyPI", "reason": "VCS/URL requirement without an immutable commit SHA"})
    entries.append({"name": name, "spec": "", "version": None, "file": path, "hash": None,
                    "source_type": st, "via": [], "url": f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"[:300]})


def _join(base: str, rel: str) -> Optional[str]:
    out = [p for p in base.split("/") if p] if base else []
    for p in rel.replace("\\", "/").split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not out:
                return None
            out.pop()
        else:
            out.append(p)
    return "/".join(out)


# --------------------------------------------------------------------------- pyproject / poetry

def _load_toml(src: RepoSource, path: str) -> dict:
    try:
        return tomllib.loads(src.read_text(path) or "")
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ManifestError(f"{path}: invalid TOML") from exc


def pyproject_declared(src: RepoSource, path: str) -> tuple[Optional[str], dict[str, tuple[str, str]]]:
    data = _load_toml(src, path)
    declared: dict[str, tuple[str, str]] = {}
    proj = data.get("project") or {}
    for dep in (proj.get("dependencies") or [])[:5000]:
        try:
            r = Requirement(dep)
            declared[norm_pypi(r.name)] = (str(r.specifier), "runtime")
        except (InvalidRequirement, TypeError):
            continue
    for group, deps in (proj.get("optional-dependencies") or {}).items():
        for dep in (deps or [])[:5000]:
            try:
                r = Requirement(dep)
                declared.setdefault(norm_pypi(r.name), (str(r.specifier), "optional"))
            except (InvalidRequirement, TypeError):
                continue
    poetry = (data.get("tool") or {}).get("poetry") or {}

    def add_poetry(deps, scope):
        for name, spec in (deps or {}).items():
            if name.lower() == "python":
                continue
            if isinstance(spec, dict):
                spec = spec.get("version") or ("git" if "git" in spec else ("path" if "path" in spec else ""))
            declared.setdefault(norm_pypi(name), (str(spec), scope))
    add_poetry(poetry.get("dependencies"), "runtime")
    add_poetry(poetry.get("dev-dependencies"), "dev")
    for gname, g in (poetry.get("group") or {}).items():
        add_poetry((g or {}).get("dependencies"), "dev" if gname in ("dev", "test", "lint", "docs") else "optional")
    name = proj.get("name") or poetry.get("name")
    return (name if isinstance(name, str) else None), declared


def parse_pyproject_only(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    name, declared = pyproject_declared(src, path)
    d = dirname(path)
    root = make_root(ctx, "PyPI", d, name or d or "python-app", path)
    ctx.declared[root.id] = {n: s for n, (s, _) in declared.items()}
    for n, (spec, scope) in declared.items():
        exact = _exact_from_specifier(spec)
        p = ctx.graph.add_package(Package(ecosystem="PyPI", name=n, version=exact, source_file=path,
                                          declared_spec=spec, version_exact=bool(exact), direct=True, scope=scope))
        ctx.graph.add_edge(root.id, p.id, "direct", spec, scope)
        if not exact:
            ctx.unpinned.append({"file": path, "name": n, "spec": spec or "(any)", "ecosystem": "PyPI",
                                 "reason": "version range without a lockfile"})
    ctx.missing_lockfiles.append({"manifest": path, "ecosystem": "PyPI"})
    return ParseOutcome(path, "PyPI", "manifest", "pyproject.toml", "partial", len(declared),
                        "Declared dependencies parsed; no lockfile found, so installed versions are not known.",
                        ["Ranges are not resolved (no dependency resolution is performed).",
                         "Transitive dependencies are unknown without poetry.lock / a pinned requirements file."])


def parse_poetry_lock(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    data = _load_toml(src, path)
    d = dirname(path)
    pyproject = f"{d}/pyproject.toml" if d else "pyproject.toml"
    name, declared = (pyproject_declared(src, pyproject) if src.exists(pyproject) else (None, {}))
    root = make_root(ctx, "PyPI", d, name or d or "python-app", pyproject if declared else path, lockfile=path)
    ctx.declared[root.id] = {n: s for n, (s, _) in declared.items()}
    pkgs = data.get("package") or []
    if not isinstance(pkgs, list) or len(pkgs) > 20000:
        raise ManifestError(f"{path}: unexpected structure or too large")
    ids: dict[str, str] = {}
    files_meta = ((data.get("metadata") or {}).get("files") or {})
    for entry in pkgs:
        if not isinstance(entry, dict):
            continue
        n = norm_pypi(str(entry.get("name", "")))
        v = safe_version(str(entry.get("version", "")))
        if not n or not v:
            continue
        files = entry.get("files") or files_meta.get(entry.get("name"), []) or []
        h = files[0].get("hash") if files and isinstance(files[0], dict) else None
        source = entry.get("source") or {}
        st = {"git": "git", "directory": "file", "file": "file", "url": "url"}.get(source.get("type"), "registry")
        if source.get("type") == "legacy":
            ctx.registries.append({"file": path, "scope": None, "kind": "poetry-source",
                                   "url": (urlparse(str(source.get("url", ""))).hostname or "")})
        cat = entry.get("category") or ("dev" if entry.get("groups") == ["dev"] else "runtime")
        p = ctx.graph.add_package(Package(ecosystem="PyPI", name=n, version=v, source_file=path, version_exact=True,
                                          integrity=h, source_type=st, scope="dev" if cat == "dev" else "runtime",
                                          resolved=str(source.get("url"))[:300] if source.get("url") else None))
        ids[n] = p.id
    for entry in pkgs:
        if not isinstance(entry, dict):
            continue
        sid = ids.get(norm_pypi(str(entry.get("name", ""))))
        for dep in (entry.get("dependencies") or {}):
            tgt = ids.get(norm_pypi(dep))
            if sid and tgt:
                ctx.graph.add_edge(sid, tgt, "depends")
    for n, (spec, scope) in declared.items():
        if n in ids:
            pkg = ctx.graph.packages[ids[n]]
            pkg.direct, pkg.declared_spec = True, spec
            ctx.graph.add_edge(root.id, ids[n], "direct", spec, scope)
            ok = versions.satisfies("PyPI", pkg.version, _poetry_to_pep440(spec))
            if ok is False:
                ctx.drift.append({"file": path, "name": n, "declared": spec, "locked": pkg.version, "ecosystem": "PyPI",
                                  "issue": "locked version does not satisfy the declared range"})
    lim = []
    if not declared:
        lim.append("pyproject.toml not found next to poetry.lock: direct vs transitive cannot be distinguished; "
                   "packages without a parent in the lockfile are attached to the project.")
        for pid in ids.values():
            if not ctx.graph.redges.get(pid):
                ctx.graph.add_edge(root.id, pid, "unknown-path")
    return ParseOutcome(path, "PyPI", "lockfile", "poetry.lock", "parsed", len(ids), "Exact versions and edges parsed.", lim)


def _poetry_to_pep440(spec: str) -> Optional[str]:
    s = (spec or "").strip()
    if not s or s == "*":
        return ""
    m = re.match(r"^\^(\d+)(?:\.(\d+))?(?:\.(\d+))?$", s)
    if m:
        a, b, c = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
        upper = f"{a + 1}.0.0" if a > 0 else (f"0.{b + 1}.0" if b > 0 else f"0.0.{c + 1}")
        return f">={a}.{b}.{c},<{upper}"
    m = re.match(r"^~(\d+)(?:\.(\d+))?(?:\.(\d+))?$", s)
    if m:
        a, b, c = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
        return f">={a}.{b}.{c},<{a}.{b + 1}.0" if m.group(2) else f">={a}.0.0,<{a + 1}.0.0"
    if re.match(r"^\d", s):
        return f"=={s}"
    return s if re.match(r"^[<>=!~]", s) else None


def parse_pipfile_lock(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    data = load_json(src.read_text(path) or "", path)
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: expected an object")
    d = dirname(path)
    pipfile = f"{d}/Pipfile" if d else "Pipfile"
    direct_names: dict[str, str] = {}
    if src.exists(pipfile):
        try:
            pf = tomllib.loads(src.read_text(pipfile) or "")
            for sect, scope in (("packages", "runtime"), ("dev-packages", "dev")):
                for n in (pf.get(sect) or {}):
                    direct_names[norm_pypi(n)] = scope
        except tomllib.TOMLDecodeError:
            pass
    root = make_root(ctx, "PyPI", d, d or "python-app", pipfile if direct_names else path, lockfile=path)
    count = 0
    for sect, scope in (("default", "runtime"), ("develop", "dev")):
        for name, entry in (data.get(sect) or {}).items():
            if not isinstance(entry, dict):
                continue
            n = norm_pypi(name)
            v = _exact_from_specifier(str(entry.get("version", "")))
            hashes = entry.get("hashes") or []
            st = "git" if entry.get("git") else ("file" if entry.get("path") else "registry")
            p = ctx.graph.add_package(Package(ecosystem="PyPI", name=n, version=v, source_file=path, version_exact=bool(v),
                                              integrity=hashes[0] if hashes else None, scope=scope, source_type=st,
                                              direct=(n in direct_names) if direct_names else False))
            rel = "direct" if direct_names and n in direct_names else "unknown-path"
            ctx.graph.add_edge(root.id, p.id, rel, None, scope)
            count += 1
    for src_entry in ((data.get("_meta") or {}).get("sources") or []):
        if isinstance(src_entry, dict) and src_entry.get("url"):
            u = urlparse(str(src_entry["url"]))
            ctx.registries.append({"file": path, "scope": None, "kind": "pipenv-source",
                                   "url": f"{u.scheme}://{u.hostname}", "insecure": u.scheme == "http"})
    return ParseOutcome(path, "PyPI", "lockfile", "Pipfile.lock", "parsed", count, "Exact versions and hashes parsed.",
                        ["Pipfile.lock does not record dependency edges: transitive paths are unknown."])
