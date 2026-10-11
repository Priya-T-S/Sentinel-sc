"""Go (go.mod/go.sum), Rust (Cargo.toml/Cargo.lock), Java (pom.xml, Gradle lockfile/build files),
.NET (packages.lock.json, *.csproj, packages.config) and CycloneDX JSON SBOMs."""
from __future__ import annotations

import re
import tomllib
from typing import Optional
from urllib.parse import unquote

import defusedxml.ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from ..models import PURL_TO_ECO, Package
from ..reposource import RepoSource, dirname
from .base import ManifestError, ParseContext, ParseOutcome, load_json, make_root, safe_name, safe_version

# --------------------------------------------------------------------------- Go


def parse_go_mod(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    text = src.read_text(path) or ""
    d = dirname(path)
    module = None
    reqs: list[tuple[str, str, bool]] = []
    replaces: list[str] = []
    in_block = None
    for raw in text.splitlines()[:50000]:
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        indirect = "// indirect" in line
        line_nc = line.split("//", 1)[0].strip()
        if line_nc.startswith("module "):
            module = line_nc.split(None, 1)[1].strip().strip('"')
            continue
        if line_nc.endswith("(") and line_nc.split()[0] in ("require", "replace", "exclude", "retract"):
            in_block = line_nc.split()[0]
            continue
        if line_nc == ")":
            in_block = None
            continue
        kind, body = (in_block, line_nc) if in_block else (line_nc.split(None, 1) + [""])[:2]
        if kind == "require":
            parts = body.split()
            if len(parts) >= 2 and safe_name(parts[0]) and safe_version(parts[1]):
                reqs.append((parts[0], parts[1], indirect))
        elif kind == "replace":
            replaces.append(body)
    root = make_root(ctx, "Go", d, module or d or "go-module", path,
                     lockfile=(f"{d}/go.sum" if d else "go.sum") if src.exists(f"{d}/go.sum" if d else "go.sum") else None)
    sums = _go_sum(src, f"{d}/go.sum" if d else "go.sum")
    declared = {}
    for name, ver, indirect in reqs:
        p = ctx.graph.add_package(Package(ecosystem="Go", name=name, version=ver, source_file=path, version_exact=True,
                                          direct=not indirect, declared_spec=ver, integrity=sums.get((name, ver)),
                                          scope="runtime" if not indirect else "unknown"))
        ctx.graph.add_edge(root.id, p.id, "direct" if not indirect else "unknown-path", ver)
        if not indirect:
            declared[name] = ver
    ctx.declared[root.id] = declared
    lim = ["Indirect modules are listed by go.mod but the module that requires them is not recorded "
           "(path shown as 'unknown path'; run `go mod graph` for exact edges)."]
    for r in replaces:
        lim.append(f"replace directive present ({r[:80]}); replaced modules are scanned at their declared version.")
        if "=>" in r and (r.split("=>")[1].strip().startswith(".") or r.split("=>")[1].strip().startswith("/")):
            ctx.unpinned.append({"file": path, "name": r.split()[0], "spec": r[:80], "ecosystem": "Go",
                                 "reason": "replace directive points to a local path"})
    return ParseOutcome(path, "Go", "manifest", "go.mod", "parsed", len(reqs),
                        f"{len(reqs)} module requirement(s); go.sum hashes {'matched' if sums else 'not found'}.", lim)


def _go_sum(src: RepoSource, path: str) -> dict:
    out = {}
    text = src.read_text(path) if src.exists(path) else None
    for line in (text or "").splitlines()[:200000]:
        parts = line.split()
        if len(parts) == 3 and not parts[1].endswith("/go.mod"):
            out[(parts[0], parts[1])] = parts[2]
    return out


# --------------------------------------------------------------------------- Rust


def parse_cargo_lock(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    try:
        data = tomllib.loads(src.read_text(path) or "")
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path}: invalid TOML") from exc
    d = dirname(path)
    pkgs = data.get("package") or []
    if not isinstance(pkgs, list) or len(pkgs) > 20000:
        raise ManifestError(f"{path}: unexpected structure or too large")
    by_name: dict[str, list[tuple[str, str]]] = {}
    local: list[dict] = []
    ids = {}
    for e in pkgs:
        if not isinstance(e, dict):
            continue
        n, v = safe_name(str(e.get("name", ""))), safe_version(str(e.get("version", "")))
        if not n or not v:
            continue
        if not e.get("source"):
            local.append(e)
            continue
        srcs = str(e.get("source"))
        st = "git" if srcs.startswith("git+") else "registry"
        p = ctx.graph.add_package(Package(ecosystem="crates.io", name=n, version=v, source_file=path, version_exact=True,
                                          integrity=f"sha256:{e['checksum']}" if e.get("checksum") else None,
                                          source_type=st, resolved=srcs[:300], scope="unknown"))
        if st == "git" and not re.search(r"#[0-9a-f]{40}$", srcs):
            ctx.unpinned.append({"file": path, "name": n, "spec": srcs[:80], "ecosystem": "crates.io",
                                 "reason": "git source without a resolved commit"})
        by_name.setdefault(n, []).append((v, p.id))
        ids[(n, v)] = p.id
    root_ids = {}
    for e in local:
        r = make_root(ctx, "crates.io", d, str(e.get("name")), f"{d}/Cargo.toml" if d else "Cargo.toml",
                      lockfile=path, sub=str(e.get("name")))
        root_ids[(e.get("name"), e.get("version"))] = r.id

    def resolve(dep: str) -> Optional[str]:
        parts = dep.split()
        cands = by_name.get(parts[0], [])
        if len(parts) >= 2:
            for v, pid in cands:
                if v == parts[1]:
                    return pid
            return None
        return cands[0][1] if len(cands) == 1 else None
    for e in pkgs:
        if not isinstance(e, dict):
            continue
        key = (e.get("name"), e.get("version"))
        sid = root_ids.get(key) or ids.get(key)
        for dep in e.get("dependencies") or []:
            tgt = resolve(str(dep))
            if sid and tgt:
                rel = "direct" if sid in root_ids.values() else "depends"
                ctx.graph.add_edge(sid, tgt, rel)
                if rel == "direct":
                    ctx.graph.packages[tgt].direct = True
    # scopes: everything reachable from roots is "runtime" unless Cargo.toml lists it as dev only
    dev_only = _cargo_dev_deps(src, f"{d}/Cargo.toml" if d else "Cargo.toml")
    for pid, pkg in ctx.graph.packages.items():
        if pkg.ecosystem == "crates.io" and path in pkg.source_file:
            pkg.scope = "dev" if (pkg.direct and pkg.name in dev_only) else "runtime"
    lim = ["Cargo.lock includes dev-dependencies alongside normal ones; dev classification uses Cargo.toml for direct deps only."]
    if not local:
        lim.append("No workspace crates found in Cargo.lock.")
    return ParseOutcome(path, "crates.io", "lockfile", "Cargo.lock", "parsed", len(ids), "Exact versions, checksums and edges parsed.", lim)


def _cargo_dev_deps(src: RepoSource, path: str) -> set:
    if not src.exists(path):
        return set()
    try:
        data = tomllib.loads(src.read_text(path) or "")
    except tomllib.TOMLDecodeError:
        return set()
    dev = set((data.get("dev-dependencies") or {}).keys())
    normal = set((data.get("dependencies") or {}).keys())
    return dev - normal


def parse_cargo_toml_only(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    try:
        data = tomllib.loads(src.read_text(path) or "")
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path}: invalid TOML") from exc
    d = dirname(path)
    name = (data.get("package") or {}).get("name") or d or "crate"
    root = make_root(ctx, "crates.io", d, str(name), path)
    n = 0
    for sect, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        for dep, spec in (data.get(sect) or {}).items():
            if isinstance(spec, dict):
                spec = spec.get("version") or ("git" if spec.get("git") else "path")
            spec = str(spec)
            exact = spec.startswith("=") and safe_version(spec[1:].strip())
            p = ctx.graph.add_package(Package(ecosystem="crates.io", name=str(dep), version=exact or None, source_file=path,
                                              declared_spec=spec, version_exact=bool(exact), direct=True, scope=scope))
            ctx.graph.add_edge(root.id, p.id, "direct", spec, scope)
            n += 1
    ctx.missing_lockfiles.append({"manifest": path, "ecosystem": "crates.io"})
    return ParseOutcome(path, "crates.io", "manifest", "Cargo.toml", "partial", n,
                        "Declared dependencies only (no Cargo.lock).",
                        ["Without Cargo.lock, installed versions and transitive dependencies are unknown."])


# --------------------------------------------------------------------------- Maven / Gradle

_MVN_SCOPE = {"compile": "runtime", "runtime": "runtime", "test": "test", "provided": "build", "system": "build", "import": "build"}


def parse_pom(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    try:
        tree = SafeET.fromstring(src.read_bytes(path) or b"", forbid_dtd=True)
    except (SafeET.ParseError, DefusedXmlException, ValueError) as exc:
        raise ManifestError(f"{path}: invalid or unsafe XML") from exc
    ns = {"m": tree.tag[1:].split("}")[0]} if tree.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)

    def text(el, tag):
        x = el.find(q(tag), ns)
        return x.text.strip() if x is not None and x.text else None
    props = {}
    pe = tree.find(q("properties"), ns)
    if pe is not None:
        for child in pe:
            props[child.tag.split("}")[-1]] = (child.text or "").strip()
    props["project.version"] = text(tree, "version") or ""
    managed = {}
    dm = tree.find(f"{q('dependencyManagement')}/{q('dependencies')}", ns)
    if dm is not None:
        for dep in dm.findall(q("dependency"), ns):
            managed[f"{text(dep, 'groupId')}:{text(dep, 'artifactId')}"] = text(dep, "version")

    def subst(v):
        if not v:
            return v
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
    d = dirname(path)
    gid, aid = text(tree, "groupId") or "", text(tree, "artifactId") or d or "maven-project"
    root = make_root(ctx, "Maven", d, f"{gid}:{aid}" if gid else aid, path)
    deps_el = tree.find(q("dependencies"), ns)
    n = 0
    unresolved = 0
    for dep in (deps_el.findall(q("dependency"), ns) if deps_el is not None else [])[:5000]:
        g, a = text(dep, "groupId"), text(dep, "artifactId")
        if not g or not a:
            continue
        name = f"{g}:{a}"
        raw = text(dep, "version") or managed.get(name)
        v = subst(raw)
        exact = v if v and "${" not in v and not re.search(r"[\[\](),]", v) else None
        if not exact:
            unresolved += 1
            ctx.unpinned.append({"file": path, "name": name, "spec": v or "(inherited)", "ecosystem": "Maven",
                                 "reason": "version range, unresolved property or inherited version"})
        scope = _MVN_SCOPE.get((text(dep, "scope") or "compile").lower(), "runtime")
        if (text(dep, "optional") or "").lower() == "true":
            scope = "optional"
        p = ctx.graph.add_package(Package(ecosystem="Maven", name=name, version=exact, source_file=path,
                                          declared_spec=v, version_exact=bool(exact), direct=True, scope=scope))
        ctx.graph.add_edge(root.id, p.id, "direct", v, scope)
        n += 1
    lim = ["Transitive Maven dependencies are not resolved (requires Maven resolution / a CycloneDX SBOM from the build).",
           "Parent POM inheritance and imported BOMs are not fetched."]
    return ParseOutcome(path, "Maven", "manifest", "pom.xml", "partial", n,
                        f"{n} direct dependenc(ies); {unresolved} without a resolvable exact version.", lim)


def parse_gradle_lockfile(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    d = dirname(path)
    root = make_root(ctx, "Maven", d, d or "gradle-project", path, lockfile=path, sub="gradle")
    n = 0
    for line in (src.read_text(path) or "").splitlines()[:50000]:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coord, _, confs = line.partition("=")
        parts = coord.split(":")
        if len(parts) != 3:
            continue
        g, a, v = parts
        cfg = confs.split(",")
        scope = "test" if all("test" in c.lower() for c in cfg if c) else "runtime"
        p = ctx.graph.add_package(Package(ecosystem="Maven", name=f"{g}:{a}", version=safe_version(v), source_file=path,
                                          version_exact=True, scope=scope))
        ctx.graph.add_edge(root.id, p.id, "unknown-path", None, scope)
        n += 1
    return ParseOutcome(path, "Maven", "lockfile", "gradle.lockfile", "parsed", n, "Locked coordinates parsed.",
                        ["Gradle lockfiles do not record edges or direct-vs-transitive; all paths are 'unknown path'."])


_GRADLE_DEP = re.compile(r"""\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt)\s*\(?\s*["']([^"':\s]+):([^"':\s]+):([^"'\s]+)["']""")


def parse_gradle_build(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    d = dirname(path)
    root = make_root(ctx, "Maven", d, d or "gradle-project", path, sub="gradle")
    n = 0
    for m in _GRADLE_DEP.finditer(src.read_text(path) or ""):
        conf, g, a, v = m.groups()
        scope = "test" if conf.startswith("test") else ("build" if conf in ("compileOnly", "annotationProcessor", "kapt") else "runtime")
        exact = v if not re.search(r"[+\[\]()$,]", v) and v not in ("latest.release", "latest.integration") else None
        if not exact:
            ctx.unpinned.append({"file": path, "name": f"{g}:{a}", "spec": v, "ecosystem": "Maven",
                                 "reason": "dynamic or interpolated Gradle version"})
        p = ctx.graph.add_package(Package(ecosystem="Maven", name=f"{g}:{a}", version=exact, source_file=path,
                                          declared_spec=v, version_exact=bool(exact), direct=True, scope=scope))
        ctx.graph.add_edge(root.id, p.id, "direct", v, scope)
        n += 1
    ctx.missing_lockfiles.append({"manifest": path, "ecosystem": "Maven"})
    return ParseOutcome(path, "Maven", "manifest", "build.gradle (pattern-based)", "partial", n,
                        "String-notation dependencies extracted with a conservative pattern.",
                        ["Gradle build scripts are programs; only literal 'group:artifact:version' declarations are recognised.",
                         "Transitive dependencies require gradle.lockfile or an SBOM."])


# --------------------------------------------------------------------------- NuGet


def parse_nuget_lock(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    data = load_json(src.read_text(path) or "", path)
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), dict):
        raise ManifestError(f"{path}: unexpected structure")
    d = dirname(path)
    root = make_root(ctx, "NuGet", d, d or "dotnet-project", path, lockfile=path)
    ids: dict[str, str] = {}
    raw: list[tuple[str, dict]] = []
    for _fw, pkgs in data["dependencies"].items():
        if not isinstance(pkgs, dict):
            continue
        for name, e in pkgs.items():
            if not isinstance(e, dict) or e.get("type") == "Project":
                continue
            n, v = safe_name(name), safe_version(str(e.get("resolved", "")))
            if not n or not v:
                continue
            direct = e.get("type") in ("Direct", "CentralTransitive") and e.get("type") == "Direct"
            p = ctx.graph.add_package(Package(ecosystem="NuGet", name=n, version=v, source_file=path, version_exact=True,
                                              direct=direct, declared_spec=e.get("requested"),
                                              integrity=f"sha512-{e['contentHash']}" if e.get("contentHash") else None))
            ids[n.lower()] = p.id
            raw.append((p.id, e))
            if direct:
                ctx.graph.add_edge(root.id, p.id, "direct", e.get("requested"))
    for pid, e in raw:
        for dep in (e.get("dependencies") or {}):
            tgt = ids.get(str(dep).lower())
            if tgt:
                ctx.graph.add_edge(pid, tgt, "depends")
    return ParseOutcome(path, "NuGet", "lockfile", "packages.lock.json", "parsed", len(ids),
                        "Exact versions, content hashes and edges parsed.",
                        ["Multiple target frameworks are merged into one graph."])


def parse_csproj(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    try:
        tree = SafeET.fromstring(src.read_bytes(path) or b"", forbid_dtd=True)
    except (SafeET.ParseError, DefusedXmlException, ValueError) as exc:
        raise ManifestError(f"{path}: invalid or unsafe XML") from exc
    d = dirname(path)
    root = make_root(ctx, "NuGet", d, path.rsplit("/", 1)[-1], path, sub=path.rsplit("/", 1)[-1])
    n = 0
    for el in tree.iter():
        tag = el.tag.split("}")[-1]
        if tag not in ("PackageReference", "package"):
            continue
        name = el.get("Include") or el.get("id")
        ver = el.get("Version") or el.get("version")
        if ver is None:
            child = next((c for c in el if c.tag.split("}")[-1] == "Version"), None)
            ver = child.text.strip() if child is not None and child.text else None
        if not safe_name(name or ""):
            continue
        exact = ver if ver and not re.search(r"[\[\](),*$]", ver) else None
        if not exact:
            ctx.unpinned.append({"file": path, "name": name, "spec": ver or "(central/unspecified)", "ecosystem": "NuGet",
                                 "reason": "floating, ranged or centrally managed version"})
        p = ctx.graph.add_package(Package(ecosystem="NuGet", name=name, version=exact, source_file=path,
                                          declared_spec=ver, version_exact=bool(exact), direct=True))
        ctx.graph.add_edge(root.id, p.id, "direct", ver)
        n += 1
    ctx.missing_lockfiles.append({"manifest": path, "ecosystem": "NuGet"})
    return ParseOutcome(path, "NuGet", "manifest", path.rsplit(".", 1)[-1], "partial", n,
                        "Direct PackageReference entries parsed.",
                        ["Transitive packages require packages.lock.json (RestorePackagesWithLockFile)."])


# --------------------------------------------------------------------------- CycloneDX


def parse_purl(purl: str) -> Optional[tuple[str, str, Optional[str]]]:
    m = re.match(r"^pkg:([a-zA-Z0-9.+-]+)/(.+?)(?:@([^?#]+))?(?:[?#].*)?$", purl or "")
    if not m:
        return None
    eco = PURL_TO_ECO.get(m.group(1).lower())
    if not eco:
        return None
    name = unquote(m.group(2))
    if eco == "Maven":
        name = name.replace("/", ":", 1)
    return eco, name, unquote(m.group(3)) if m.group(3) else None


def parse_cyclonedx(src: RepoSource, path: str, ctx: ParseContext) -> ParseOutcome:
    data = load_json(src.read_text(path) or "", path)
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise ManifestError(f"{path}: not a CycloneDX JSON document")
    meta_comp = (data.get("metadata") or {}).get("component") or {}
    root = make_root(ctx, "SBOM", dirname(path), meta_comp.get("name") or path.rsplit("/", 1)[-1], path, sub=path.rsplit("/", 1)[-1])
    ref_to_id: dict[str, str] = {}
    skipped = 0
    count = 0

    def walk(comps, depth=0):
        nonlocal skipped, count
        if depth > 10:
            return
        for c in comps or []:
            if not isinstance(c, dict):
                continue
            count += 1
            if count > 20000:
                raise ManifestError(f"{path}: SBOM exceeds component limit")
            parsed = parse_purl(str(c.get("purl", "")))
            if not parsed:
                skipped += 1
                walk(c.get("components"), depth + 1)
                continue
            eco, name, ver = parsed
            ver = safe_version(ver or c.get("version") or "")
            hashes = c.get("hashes") or []
            h = next((f"{x.get('alg')}:{x.get('content')}" for x in hashes if isinstance(x, dict) and x.get("content")), None)
            scope = {"optional": "optional", "excluded": "dev"}.get(str(c.get("scope", "")), "runtime")
            lic = None
            for l in c.get("licenses") or []:
                if isinstance(l, dict):
                    lic = (l.get("license") or {}).get("id") or (l.get("license") or {}).get("name") or l.get("expression")
                    if lic:
                        break
            p = ctx.graph.add_package(Package(ecosystem=eco, name=name, version=ver, source_file=path,
                                              version_exact=bool(ver), integrity=h, scope=scope, license=lic))
            if c.get("bom-ref"):
                ref_to_id[str(c["bom-ref"])] = p.id
            walk(c.get("components"), depth + 1)
    walk(data.get("components"))
    meta_ref = meta_comp.get("bom-ref")
    has_deps = False
    for dep in data.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        ref = str(dep.get("ref"))
        sid = root.id if ref == meta_ref else ref_to_id.get(ref)
        for t in dep.get("dependsOn") or []:
            tid = ref_to_id.get(str(t))
            if sid and tid:
                has_deps = True
                ctx.graph.add_edge(sid, tid, "direct" if sid == root.id else "depends")
                if sid == root.id:
                    ctx.graph.packages[tid].direct = True
    lim = []
    for pid in set(ref_to_id.values()) | {p.id for p in ctx.graph.packages.values() if path in p.source_file}:
        if not ctx.graph.redges.get(pid):
            ctx.graph.add_edge(root.id, pid, "unknown-path")
    if not has_deps:
        lim.append("SBOM has no dependency relationships; all components are attached with an unknown path.")
    if skipped:
        lim.append(f"{skipped} component(s) without a supported package URL were skipped.")
    lim.append("No source code accompanies an SBOM, so reachability cannot be assessed.")
    return ParseOutcome(path, "SBOM", "sbom", f"CycloneDX {data.get('specVersion', '?')} JSON",
                        "parsed" if not skipped else "partial", len(set(ref_to_id.values())),
                        "Components (purl) and dependency relationships imported.", lim)
