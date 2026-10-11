"""Core data model: packages, dependency edges, and the dependency graph."""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import quote

ECOSYSTEMS = ("npm", "PyPI", "Go", "crates.io", "Maven", "NuGet")
PURL_TYPES = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo", "Maven": "maven", "NuGet": "nuget"}
PURL_TO_ECO = {v: k for k, v in PURL_TYPES.items()}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}


def package_id(ecosystem: str, name: str, version: Optional[str]) -> str:
    return f"{ecosystem}:{name}@{version or '?'}"


def make_purl(ecosystem: str, name: str, version: Optional[str]) -> Optional[str]:
    t = PURL_TYPES.get(ecosystem)
    if not t:
        return None
    if ecosystem == "Maven" and ":" in name:
        group, art = name.split(":", 1)
        base = f"pkg:maven/{quote(group)}/{quote(art)}"
    elif ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, n = name.split("/", 1)
        base = f"pkg:npm/{quote(scope)}/{quote(n)}"
    elif ecosystem == "Go":
        base = f"pkg:golang/{name}"
    else:
        base = f"pkg:{t}/{quote(name)}"
    return f"{base}@{quote(version)}" if version else base


@dataclass
class Package:
    ecosystem: str
    name: str
    version: Optional[str]              # exact version when known; None when only a range is declared
    source_file: str                    # manifest/lockfile the record came from (repo-relative)
    declared_spec: Optional[str] = None  # version spec as written in the manifest (direct deps)
    version_exact: bool = False          # True when the version came from a lockfile / exact pin
    direct: bool = False
    scope: str = "runtime"               # runtime | dev | optional | peer | build | test | unknown
    integrity: Optional[str] = None      # e.g. "sha512-..." / "sha256:..."
    resolved: Optional[str] = None       # resolved tarball / source URL
    source_type: str = "registry"        # registry | git | file | url | workspace | unknown
    has_install_script: Optional[bool] = None
    local_path: Optional[str] = None     # repo-relative path for file:/workspace deps
    license: Optional[str] = None
    notes: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return package_id(self.ecosystem, self.name, self.version)

    @property
    def purl(self) -> Optional[str]:
        return make_purl(self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["purl"] = self.purl
        return d


@dataclass
class Root:
    """An application component (one manifest/project) that owns dependencies."""
    id: str
    name: str
    ecosystem: str
    manifest: str
    lockfile: Optional[str] = None


class DependencyGraph:
    """Directed graph: root -> direct deps -> transitive deps.

    Edges are only added when a manifest/lockfile states the relationship. When a
    format does not record relationships (e.g. requirements.txt, go.mod indirect
    entries) the package is attached to its root with `relation="unknown-path"` so
    the UI can show that the path is not established.
    """

    MAX_PATHS = 50
    MAX_DEPTH = 64

    def __init__(self):
        self.roots: dict[str, Root] = {}
        self.packages: dict[str, Package] = {}
        self.edges: dict[str, dict[str, dict]] = {}   # from -> to -> attrs
        self.redges: dict[str, set[str]] = {}

    # ------------------------------------------------------------------ build
    def add_root(self, root: Root) -> Root:
        self.roots.setdefault(root.id, root)
        self.edges.setdefault(root.id, {})
        return self.roots[root.id]

    def add_package(self, pkg: Package) -> Package:
        existing = self.packages.get(pkg.id)
        if existing is None:
            self.packages[pkg.id] = pkg
            self.edges.setdefault(pkg.id, {})
            return pkg
        # merge: keep the strongest evidence
        existing.direct = existing.direct or pkg.direct
        if existing.scope != "runtime" and pkg.scope == "runtime":
            existing.scope = "runtime"
        for attr in ("integrity", "resolved", "declared_spec", "local_path", "license"):
            if not getattr(existing, attr) and getattr(pkg, attr):
                setattr(existing, attr, getattr(pkg, attr))
        if existing.has_install_script is None:
            existing.has_install_script = pkg.has_install_script
        existing.version_exact = existing.version_exact or pkg.version_exact
        if pkg.source_file not in existing.source_file.split(", "):
            existing.source_file = f"{existing.source_file}, {pkg.source_file}"
        return existing

    def add_edge(self, src: str, dst: str, relation: str = "depends", spec: Optional[str] = None, scope: Optional[str] = None):
        if src == dst:
            return
        self.edges.setdefault(src, {})
        if dst not in self.edges[src]:
            self.edges[src][dst] = {"relation": relation, "spec": spec, "scope": scope}
        self.redges.setdefault(dst, set()).add(src)

    # ------------------------------------------------------------------ queries
    def depth_map(self) -> dict[str, int]:
        """Shortest distance from any root (roots = 0, direct deps = 1)."""
        depth: dict[str, int] = {}
        q = deque()
        for r in self.roots:
            depth[r] = 0
            q.append(r)
        while q:
            n = q.popleft()
            for m in self.edges.get(n, {}):
                if m not in depth:
                    depth[m] = depth[n] + 1
                    q.append(m)
        return depth

    def paths_to(self, target: str, limit: int = MAX_PATHS) -> list[list[str]]:
        """All simple root->target paths (bounded), shortest first."""
        results: list[list[str]] = []
        # reverse DFS from target to roots, bounded
        stack = [(target, [target])]
        steps = 0
        while stack and len(results) < limit * 4 and steps < 50_000:
            steps += 1
            node, path = stack.pop()
            if node in self.roots:
                results.append(list(reversed(path)))
                continue
            if len(path) > self.MAX_DEPTH:
                continue
            for parent in sorted(self.redges.get(node, ())):
                if parent not in path:
                    stack.append((parent, path + [parent]))
        results.sort(key=len)
        return results[:limit]

    def dependents_count(self, target: str) -> int:
        """How many distinct packages/roots transitively depend on target (blast radius)."""
        seen = set()
        q = deque([target])
        while q:
            n = q.popleft()
            for p in self.redges.get(n, ()):
                if p not in seen:
                    seen.add(p)
                    q.append(p)
        return len(seen)

    def affected_roots(self, target: str) -> list[str]:
        seen = set()
        q = deque([target])
        roots = []
        while q:
            n = q.popleft()
            if n in self.roots and n not in roots:
                roots.append(n)
            for p in self.redges.get(n, ()):
                if p not in seen:
                    seen.add(p)
                    q.append(p)
        return roots

    def direct_ancestors(self, target: str) -> list[str]:
        """Direct dependencies of any root through which target is reached."""
        out = []
        for path in self.paths_to(target):
            if len(path) >= 2 and path[1] not in out:
                out.append(path[1])
        return out

    def parents(self, target: str) -> list[str]:
        return sorted(p for p in self.redges.get(target, ()) if p not in self.roots)

    def stats(self) -> dict:
        depth = self.depth_map()
        direct = sum(1 for p in self.packages.values() if p.direct)
        unreachable = [pid for pid in self.packages if pid not in depth]
        by_eco: dict[str, int] = {}
        for p in self.packages.values():
            by_eco[p.ecosystem] = by_eco.get(p.ecosystem, 0) + 1
        return {
            "packages": len(self.packages),
            "direct": direct,
            "transitive": len(self.packages) - direct,
            "edges": sum(len(v) for v in self.edges.values()),
            "roots": len(self.roots),
            "max_depth": max(depth.values()) if depth else 0,
            "unattached": len(unreachable),
            "by_ecosystem": by_eco,
        }

    def to_dict(self) -> dict:
        depth = self.depth_map()
        nodes = []
        for r in self.roots.values():
            nodes.append({"id": r.id, "type": "root", "name": r.name, "ecosystem": r.ecosystem,
                          "manifest": r.manifest, "lockfile": r.lockfile, "depth": 0})
        for p in self.packages.values():
            d = p.to_dict()
            d["type"] = "package"
            d["depth"] = depth.get(p.id)
            d["dependents"] = len(self.redges.get(p.id, ()))
            nodes.append(d)
        edges = [{"from": s, "to": t, **attrs} for s, tos in self.edges.items() for t, attrs in tos.items()]
        return {"nodes": nodes, "edges": edges}
