"""Static reachability evidence (import + call-site analysis, no execution).

Levels (strongest evidence first):
  symbol_call            Application source imports the package AND calls a symbol named by the advisory
                         (OSV `ecosystem_specific` symbols, or identifiers quoted in the advisory text).
  imported               Application source imports the vulnerable package; no affected symbol identified.
  transitive_imported    Package is reached via a dependency the application imports.
  transitive             Package is only reached through other dependencies whose usage is not established.
  declared_not_imported  Direct dependency, but no import was found in the scanned source files.
  unknown                No application source available (lockfile/SBOM-only input).

None of these levels claim exploitability. A call site shows that affected code CAN run; whether
attacker-controlled input reaches it requires further (manual or dynamic) analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..config import LIMITS
from ..models import DependencyGraph, Package
from ..parsers import SKIP_DIRS
from ..parsers.base import norm_pypi
from ..reposource import RepoSource

JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte")
PY_EXT = (".py",)
GO_EXT = (".go",)

# distribution name -> import names (only where they differ)
PY_IMPORT_NAMES = {
    "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"], "pillow": ["PIL"], "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"], "python-dateutil": ["dateutil"], "pyjwt": ["jwt"], "python-dotenv": ["dotenv"],
    "psycopg2-binary": ["psycopg2"], "pymysql": ["pymysql"], "protobuf": ["google.protobuf"], "attrs": ["attr", "attrs"],
    "msgpack-python": ["msgpack"], "pycryptodome": ["Crypto"], "typing-extensions": ["typing_extensions"],
    "markupsafe": ["markupsafe"], "jinja2": ["jinja2"], "django-rest-framework": ["rest_framework"], "djangorestframework": ["rest_framework"],
}

_COMMON_WORDS = {"this", "that", "with", "from", "version", "versions", "function", "functions", "package", "packages",
                 "object", "string", "value", "values", "input", "user", "data", "options", "option", "attacker",
                 "vulnerable", "vulnerability", "affected", "prior", "using", "used", "allows", "allow", "when", "which",
                 "could", "would", "should", "property", "properties", "prototype", "request", "response", "server",
                 "client", "default", "true", "false", "null", "undefined", "length", "type", "types", "call", "calls",
                 "code", "array", "index", "error", "patch", "issue", "upgrade", "update", "release", "method", "methods",
                 "module", "require", "import", "export", "return", "argument", "arguments", "parameter", "parameters",
                 "regular", "expression", "denial", "service", "injection", "pollution", "command", "execution"}


@dataclass
class ImportSite:
    file: str
    line: int
    binding: Optional[str]   # local identifier bound to the module (e.g. "_" for lodash)
    names: list = field(default_factory=list)  # destructured / from-imported names
    subpath: Optional[str] = None              # e.g. "template" for require('lodash/template')
    snippet: str = ""
    is_test: bool = False


@dataclass
class SourceIndex:
    files_scanned: int = 0
    languages: dict = field(default_factory=dict)
    imports: dict = field(default_factory=dict)   # (ecosystem, pkg_name) -> [ImportSite]
    texts: dict = field(default_factory=dict)     # file -> text (bounded)
    truncated: bool = False

    def to_summary(self) -> dict:
        return {"files_scanned": self.files_scanned, "languages": self.languages, "truncated": self.truncated,
                "imported_packages": len(self.imports)}


_JS_IMPORT_RES = [
    # import x from 'm' / import * as x from 'm' / import {a, b as c} from 'm' / import x, {a} from 'm'
    re.compile(r"""^\s*import\s+(?:(?P<def>[\w$]+)\s*,?\s*)?(?:\*\s*as\s+(?P<ns>[\w$]+))?\s*(?:\{(?P<named>[^}]*)\})?\s*from\s*['"](?P<mod>[^'"]+)['"]"""),
    # const x = require('m') / const {a, b: c} = require('m')
    re.compile(r"""(?:const|let|var)\s+(?:(?P<def>[\w$]+)|\{(?P<named>[^}]*)\})\s*=\s*require\(\s*['"](?P<mod>[^'"]+)['"]\s*\)"""),
    # bare require / dynamic import
    re.compile(r"""(?:require|import)\(\s*['"](?P<mod>[^'"]+)['"]\s*\)"""),
    re.compile(r"""^\s*import\s+['"](?P<mod>[^'"]+)['"]"""),
]
_NODE_BUILTINS = {"fs", "path", "http", "https", "url", "util", "os", "crypto", "child_process", "events", "stream",
                  "net", "dns", "zlib", "buffer", "querystring", "assert", "tls", "readline", "process", "vm", "worker_threads"}


def _js_pkg(spec: str) -> tuple[Optional[str], Optional[str]]:
    if spec.startswith((".", "/", "node:")) or spec in _NODE_BUILTINS:
        return None, None
    parts = spec.split("/")
    if spec.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2]), "/".join(parts[2:]) or None
    return parts[0], "/".join(parts[1:]) or None


def _is_test(path: str) -> bool:
    return bool(re.search(r"(^|/)(tests?|__tests__|spec)(/|$)|\.(test|spec)\.[jt]sx?$|(^|/)test_[^/]*\.py$", path))


def build_index(src: RepoSource, graph: DependencyGraph) -> SourceIndex:
    idx = SourceIndex()
    local_pkg_dirs = {p.local_path for p in graph.packages.values() if p.local_path}
    go_modules = sorted({p.name for p in graph.packages.values() if p.ecosystem == "Go"}, key=len, reverse=True)
    for path in src.list_files():
        parts = path.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]) or any(path.startswith(d + "/") for d in local_pkg_dirs if d):
            continue
        if not path.endswith(JS_EXT + PY_EXT + GO_EXT) or path.endswith(".d.ts") or ".min." in path:
            continue
        if idx.files_scanned >= LIMITS.max_source_files_for_reachability:
            idx.truncated = True
            break
        text = src.read_text(path, LIMITS.max_source_file_bytes)
        if text is None:
            continue
        idx.files_scanned += 1
        lang = "javascript" if path.endswith(JS_EXT) else ("python" if path.endswith(PY_EXT) else "go")
        idx.languages[lang] = idx.languages.get(lang, 0) + 1
        idx.texts[path] = text
        test = _is_test(path)
        if lang == "javascript":
            _index_js(idx, path, text, test)
        elif lang == "python":
            _index_py(idx, path, text, test)
        else:
            _index_go(idx, path, text, test, go_modules)
    return idx


def _names(raw: Optional[str]) -> list[str]:
    out = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        # "a as b" (ESM) or "a: b" (CJS destructuring) -> record original name
        out.append(re.split(r"\s+as\s+|\s*:\s*", part)[0].strip())
    return out


def _index_js(idx: SourceIndex, path: str, text: str, test: bool):
    for lineno, line in enumerate(text.splitlines()[:20000], 1):
        if "require" not in line and "import" not in line:
            continue
        for rx in _JS_IMPORT_RES:
            for m in rx.finditer(line):
                mod = m.group("mod")
                pkg, sub = _js_pkg(mod)
                if not pkg:
                    continue
                gd = m.groupdict()
                site = ImportSite(path, lineno, gd.get("def") or gd.get("ns"), _names(gd.get("named")), sub,
                                  line.strip()[:200], test)
                key = ("npm", pkg)
                lst = idx.imports.setdefault(key, [])
                if not any(s.file == path and s.line == lineno for s in lst):
                    lst.append(site)


def _index_py(idx: SourceIndex, path: str, text: str, test: bool):
    for lineno, line in enumerate(text.splitlines()[:20000], 1):
        s = line.strip()
        m = re.match(r"^import\s+([\w.]+)(?:\s+as\s+(\w+))?", s)
        if m:
            top = m.group(1)
            idx.imports.setdefault(("PyPI-import", top.split(".")[0]), []).append(
                ImportSite(path, lineno, m.group(2) or top, [], top, s[:200], test))
            continue
        m = re.match(r"^from\s+([\w.]+)\s+import\s+(.+)$", s)
        if m and not m.group(1).startswith("."):
            top = m.group(1)
            names = [n.split(" as ")[0].strip(" ()") for n in m.group(2).split(",")]
            idx.imports.setdefault(("PyPI-import", top.split(".")[0]), []).append(
                ImportSite(path, lineno, None, names, top, s[:200], test))


def _index_go(idx: SourceIndex, path: str, text: str, test: bool, modules: list[str]):
    for lineno, line in enumerate(text.splitlines()[:20000], 1):
        for m in re.finditer(r'(?:^\s*import\s+|^\s*)(?:(\w+)\s+)?"([\w.\-/]+)"', line):
            imp = m.group(2)
            mod = next((mm for mm in modules if imp == mm or imp.startswith(mm + "/")), None)
            if mod:
                alias = m.group(1) or imp.rsplit("/", 1)[-1]
                idx.imports.setdefault(("Go", mod), []).append(ImportSite(path, lineno, alias, [], imp, line.strip()[:200], test))


def imports_for(idx: SourceIndex, pkg: Package) -> list[ImportSite]:
    if pkg.ecosystem == "npm":
        return idx.imports.get(("npm", pkg.name), [])
    if pkg.ecosystem == "PyPI":
        names = PY_IMPORT_NAMES.get(norm_pypi(pkg.name), [pkg.name.replace("-", "_"), pkg.name.replace("-", "_").lower()])
        out = []
        for n in names:
            out.extend(idx.imports.get(("PyPI-import", n.split(".")[0]), []))
        return out
    if pkg.ecosystem == "Go":
        return idx.imports.get(("Go", pkg.name), [])
    return []


def advisory_symbols(advisory: dict) -> tuple[list[str], str]:
    """Symbols from structured OSV data, else identifiers quoted/called in advisory text."""
    if advisory.get("symbols"):
        return list(advisory["symbols"]), "OSV ecosystem_specific symbol list"
    text = f"{advisory.get('summary', '')}\n{advisory.get('details', '')}"
    cands = set(re.findall(r"`(?:[\w$]+\.)?([A-Za-z_$][\w$]{3,40})(?:\(\))?`", text))
    cands |= set(re.findall(r"\b(?:[\w$]+\.)?([a-z][A-Za-z0-9_$]{3,40})\s*\(\)", text))
    cands |= set(re.findall(r"\b([a-z]+[A-Z][A-Za-z0-9]{2,40})\b", text))  # camelCase identifiers
    cands |= set(re.findall(r"(?:function|method)s?\s+[`'\"]?([A-Za-z_$][\w$]{3,40})", text))
    cands |= set(re.findall(r"[`'\"]?([A-Za-z_$][\w$]{3,40})[`'\"]?\s+(?:function|method)", text))
    cands = {c for c in cands if c.lower() not in _COMMON_WORDS}
    return sorted(cands), "identifiers mentioned in advisory text (heuristic extraction)"


def find_symbol_calls(idx: SourceIndex, sites: list[ImportSite], symbols: list[str], ecosystem: str) -> list[dict]:
    if not symbols:
        return []
    hits = []
    # A package/module name is never itself an "affected symbol" (avoids matching the import line).
    module_names = set()
    for site in sites:
        if site.subpath:
            module_names.add(site.subpath.split("/")[0].split(".")[0].lower())
        if site.binding:
            module_names.add(site.binding.lower())
    sym_set = {s for s in symbols if s.lower() not in module_names}
    for site in sites:
        text = idx.texts.get(site.file, "")
        # 1) submodule import that IS the symbol: require('lodash/template') / from yaml.constructor import ...
        sub_leaf = None
        if site.subpath and ecosystem == "npm":
            sub_leaf = site.subpath.split("/")[-1].split(".")[0] if site.subpath else None
        elif site.subpath and "." in site.subpath:
            sub_leaf = site.subpath.split(".")[-1]
        if sub_leaf:
            leaf = sub_leaf
            if leaf in sym_set:
                hits.append({"file": site.file, "line": site.line, "symbol": leaf, "snippet": site.snippet,
                             "how": f"imports affected submodule '{site.subpath}'", "is_test": site.is_test})
        # 2) named import of the symbol: import { template } / const { merge } = require(...)
        for n in site.names:
            if n in sym_set:
                for ln, line in _find_lines(text, rf"(?<![\w$.]){re.escape(n)}\s*\("):
                    hits.append({"file": site.file, "line": ln, "symbol": n, "snippet": line,
                                 "how": f"calls '{n}' imported from the package", "is_test": site.is_test})
        # 3) member call on the module binding: _.template(  / yaml.load(
        if site.binding:
            for sym in sym_set:
                for ln, line in _find_lines(text, rf"(?<![\w$]){re.escape(site.binding)}\.{re.escape(sym)}\s*\("):
                    hits.append({"file": site.file, "line": ln, "symbol": sym, "snippet": line,
                                 "how": f"calls '{site.binding}.{sym}()'", "is_test": site.is_test})
    uniq = {}
    for h in hits:
        uniq[(h["file"], h["line"], h["symbol"])] = h
    return sorted(uniq.values(), key=lambda h: (h["is_test"], h["file"], h["line"]))[:20]


def _find_lines(text: str, pattern: str):
    rx = re.compile(pattern)
    for i, line in enumerate(text.splitlines()[:20000], 1):
        s = line.strip()
        if s.startswith(("//", "#", "*")):
            continue
        if rx.search(line):
            yield i, s[:200]


def assess(idx: SourceIndex, graph: DependencyGraph, pkg: Package, advisory: Optional[dict]) -> dict:
    if idx.files_scanned == 0:
        return {"level": "unknown", "label": "Unknown - no application source",
                "explanation": "The scanned input contains no application source files (lockfile/SBOM only), so imports "
                               "and call sites cannot be checked.",
                "evidence": [], "needed": "Scan the full repository to look for imports and call sites."}
    sites = imports_for(idx, pkg)
    prod_sites = [s for s in sites if not s.is_test]
    if sites:
        symbols, sym_src = advisory_symbols(advisory or {}) if advisory else ([], "")
        pkg_tokens = {pkg.name.lower(), pkg.name.lower().replace("-", "_"), pkg.name.split("/")[-1].lower()}
        symbols = [s for s in symbols if s.lower() not in pkg_tokens]
        calls = find_symbol_calls(idx, sites, symbols, pkg.ecosystem) if symbols else []
        imp_ev = [{"file": s.file, "line": s.line, "snippet": s.snippet, "kind": "import", "is_test": s.is_test} for s in sites[:10]]
        if calls:
            prod_calls = [c for c in calls if not c["is_test"]]
            return {"level": "symbol_call",
                    "label": "Static call-site evidence" + ("" if prod_calls else " (tests only)"),
                    "explanation": f"Application code calls {', '.join(sorted({c['symbol'] for c in calls}))}, which the advisory "
                                   f"identifies as affected (symbol source: {sym_src}). This shows the vulnerable code path "
                                   f"can execute; it does not prove attacker-controlled input reaches it.",
                    "symbols_considered": symbols[:20], "symbol_source": sym_src,
                    "evidence": [{**c, "kind": "call"} for c in calls] + imp_ev,
                    "needed": "Confirm whether untrusted input flows into the cited call(s)."}
        return {"level": "imported", "label": "Imported by application" + ("" if prod_sites else " (tests only)"),
                "explanation": f"{pkg.name} is imported in {len({s.file for s in sites})} file(s). "
                               + (f"No call to an advisory-named symbol ({', '.join(symbols[:6])}) was found."
                                  if symbols else "The advisory does not name specific affected functions."),
                "symbols_considered": symbols[:20], "symbol_source": sym_src,
                "evidence": imp_ev,
                "needed": "Identify which functions of the package are affected and whether the application calls them."}
    # not directly imported
    if pkg.direct:
        roots_direct = any(attrs.get("relation") == "direct" for r in graph.roots for t, attrs in graph.edges.get(r, {}).items() if t == pkg.id)
        if roots_direct and pkg.ecosystem in ("npm", "PyPI", "Go") and not graph.redges.get(pkg.id, set()) - set(graph.roots):
            return {"level": "declared_not_imported", "label": "Declared, no import found",
                    "explanation": f"{pkg.name} is a direct dependency but no import was found in {idx.files_scanned} scanned "
                                   f"source file(s). It may be unused, used by tooling/CLI, or loaded dynamically.",
                    "evidence": [], "needed": "Remove the dependency if unused; otherwise locate dynamic loading."}
    parents_imported = []
    for path in graph.paths_to(pkg.id, limit=20):
        if len(path) >= 3:
            d = graph.packages.get(path[1])
            if d and imports_for(idx, d):
                parents_imported.append(d.name)
    if parents_imported:
        uniq = sorted(set(parents_imported))
        return {"level": "transitive_imported", "label": "Reached via imported dependency",
                "explanation": f"{pkg.name} is not imported directly; it is loaded by {', '.join(uniq[:5])}, which the application "
                               f"imports. Whether the application's use of {uniq[0]} triggers the vulnerable code in {pkg.name} "
                               f"is not established by static import analysis.",
                "evidence": [{"kind": "path", "via": uniq}],
                "needed": f"Check whether the features of {uniq[0]} that the application uses call into {pkg.name}'s affected code."}
    return {"level": "transitive", "label": "Transitive only",
            "explanation": f"{pkg.name} is reached only through other dependencies, none of which were found imported in the scanned "
                           f"source.", "evidence": [], "needed": "Determine whether the parent dependency is used at runtime."}
