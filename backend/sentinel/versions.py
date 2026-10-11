"""Ecosystem-aware version parsing, comparison and range evaluation.

Version strings are NEVER compared lexicographically. Each ecosystem gets a
comparator that follows its published ordering rules as closely as practical:

* npm / crates.io / Go  -> Semantic Versioning 2.0 precedence (Go accepts a leading "v")
* PyPI                  -> PEP 440 via the `packaging` library
* Maven / Gradle        -> a ComparableVersion-style tokenizer (qualifier ordering)
* NuGet                 -> NuGet SemVer (4 numeric parts + prerelease)
* anything else         -> a conservative tokenizer (numeric runs compare numerically)

If a version cannot be parsed for its ecosystem, comparison raises
`VersionError` so callers can mark results as "unknown" instead of guessing.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Callable, Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class VersionError(ValueError):
    """Raised when a version or range cannot be interpreted safely."""


# --------------------------------------------------------------------------- semver

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
# Looser form used for crates / Go / partial npm versions such as "1.2" (padded with zeros).
_LOOSE_SEMVER_RE = re.compile(r"^[v=\s]*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple = ()

    @classmethod
    def parse(cls, text: str, loose: bool = True) -> "SemVer":
        if not isinstance(text, str) or len(text) > 256:
            raise VersionError("invalid semver")
        s = text.strip()
        m = _SEMVER_RE.match(s)
        if not m and loose:
            m2 = _LOOSE_SEMVER_RE.match(s)
            if m2:
                major, minor, patch, pre, _build = m2.groups()
                return cls(int(major), int(minor or 0), int(patch or 0), _pre_tuple(pre))
        if not m:
            raise VersionError(f"invalid semver: {text[:64]!r}")
        major, minor, patch, pre, _build = m.groups()
        return cls(int(major), int(minor), int(patch), _pre_tuple(pre))

    def key(self):
        # A version without prerelease has higher precedence than one with.
        if not self.prerelease:
            pre_key = (1,)
        else:
            parts = []
            for p in self.prerelease:
                # numeric identifiers sort lower than alphanumeric ones
                parts.append((0, p, "") if isinstance(p, int) else (1, 0, p))
            pre_key = (0, tuple(parts))
        return (self.major, self.minor, self.patch, pre_key)

    def __lt__(self, other: "SemVer") -> bool:
        return self.key() < other.key()

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += "-" + ".".join(str(p) for p in self.prerelease)
        return base


def _pre_tuple(pre: Optional[str]) -> tuple:
    if not pre:
        return ()
    out = []
    for ident in pre.split("."):
        out.append(int(ident) if ident.isdigit() else ident)
    return tuple(out)


def _cmp_semver(a: str, b: str) -> int:
    ka, kb = SemVer.parse(a).key(), SemVer.parse(b).key()
    return (ka > kb) - (ka < kb)


# --------------------------------------------------------------------------- PEP 440

def _cmp_pep440(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as exc:
        raise VersionError(str(exc)) from exc
    return (va > vb) - (va < vb)


# --------------------------------------------------------------------------- Maven

_MAVEN_QUALIFIERS = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3,
                     "rc": 4, "cr": 4, "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


def _maven_tokens(v: str):
    v = v.strip().lower()
    if not v or len(v) > 256:
        raise VersionError("invalid maven version")
    tokens = re.findall(r"\d+|[a-z]+", v)
    out = []
    for t in tokens:
        if t.isdigit():
            out.append((1, int(t), 0))
        else:
            q = _MAVEN_QUALIFIERS.get(t)
            out.append((0, q, "") if q is not None else (0, 0, t))
    # strip trailing zero / release qualifiers ("1.0.0" == "1")
    while out and (out[-1] == (1, 0, 0) or out[-1] == (0, 6, "")):
        out.pop()
    return out


def _cmp_maven(a: str, b: str) -> int:
    ta, tb = _maven_tokens(a), _maven_tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x == y:
            continue
        # padding: a missing numeric token counts as 0, a missing qualifier as "release"
        if x is None:
            x = (1, 0, 0) if y[0] == 1 else (0, 6, "")
        if y is None:
            y = (1, 0, 0) if x[0] == 1 else (0, 6, "")
        if x == y:
            continue
        # numeric tokens sort above qualifiers except "sp"
        if x[0] != y[0]:
            if x[0] == 1:
                return 1 if y[1] != 7 else -1
            return -1 if x[1] != 7 else 1
        if x[0] == 1:
            return (x[1] > y[1]) - (x[1] < y[1])
        if x[1] != y[1]:
            return (x[1] > y[1]) - (x[1] < y[1])
        return (x[2] > y[2]) - (x[2] < y[2])
    return 0


# --------------------------------------------------------------------------- NuGet

_NUGET_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def _cmp_nuget(a: str, b: str) -> int:
    def key(v):
        m = _NUGET_RE.match(v.strip())
        if not m:
            raise VersionError(f"invalid nuget version: {v[:64]!r}")
        nums = tuple(int(x or 0) for x in m.groups()[:4])
        pre = m.group(5)
        if not pre:
            return nums + ((1,),)
        parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in pre.split("."))
        return nums + ((0, parts),)
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


# --------------------------------------------------------------------------- generic

def _cmp_generic(a: str, b: str) -> int:
    def key(v):
        toks = re.findall(r"\d+|[A-Za-z]+", v)
        if not toks:
            raise VersionError("invalid version")
        return [(1, int(t), "") if t.isdigit() else (0, 0, t.lower()) for t in toks]
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


_COMPARATORS: dict[str, Callable[[str, str], int]] = {
    "npm": _cmp_semver,
    "crates.io": _cmp_semver,
    "Go": _cmp_semver,
    "PyPI": _cmp_pep440,
    "Maven": _cmp_maven,
    "NuGet": _cmp_nuget,
}


def compare(ecosystem: str, a: str, b: str) -> int:
    """Return -1/0/1. Raises VersionError when either version is unparsable."""
    fn = _COMPARATORS.get(ecosystem, _cmp_generic)
    return fn(a, b)


def is_valid(ecosystem: str, v: str) -> bool:
    try:
        compare(ecosystem, v, v)
        return True
    except VersionError:
        return False


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    valid = [v for v in versions if is_valid(ecosystem, v)]
    return sorted(valid, key=functools.cmp_to_key(lambda x, y: compare(ecosystem, x, y)))


def is_prerelease(ecosystem: str, v: str) -> bool:
    try:
        if ecosystem == "PyPI":
            return Version(v).is_prerelease
        if ecosystem in ("npm", "crates.io", "Go"):
            return bool(SemVer.parse(v).prerelease)
    except (VersionError, InvalidVersion):
        return False
    return bool(re.search(r"(alpha|beta|rc|snapshot|milestone|-)", v, re.I))


def major_of(ecosystem: str, v: str) -> Optional[int]:
    try:
        if ecosystem == "PyPI":
            return Version(v).release[0]
        if ecosystem in ("npm", "crates.io", "Go"):
            return SemVer.parse(v).major
        m = re.match(r"\D*(\d+)", v)
        return int(m.group(1)) if m else None
    except (VersionError, InvalidVersion):
        return None


def is_major_change(ecosystem: str, old: str, new: str) -> Optional[bool]:
    """True if `new` crosses a breaking-change boundary relative to `old`.

    For semver ecosystems a 0.x minor bump is also breaking (per semver/npm caret rules).
    """
    try:
        if ecosystem in ("npm", "crates.io", "Go"):
            a, b = SemVer.parse(old), SemVer.parse(new)
            if a.major != b.major:
                return True
            if a.major == 0 and a.minor != b.minor:
                return True
            return False
    except VersionError:
        return None
    ma, mb = major_of(ecosystem, old), major_of(ecosystem, new)
    if ma is None or mb is None:
        return None
    return ma != mb


# --------------------------------------------------------------------------- OSV ranges

def osv_affected(ecosystem: str, version: str, affected: dict) -> Optional[bool]:
    """Evaluate one OSV `affected[]` entry against an installed version.

    Returns True/False, or None when the entry cannot be evaluated (e.g. only GIT ranges
    or unparsable versions). The explicit `versions` list is honoured first.
    """
    versions = affected.get("versions") or []
    if version in versions:
        return True
    ranges = [r for r in (affected.get("ranges") or []) if r.get("type") in ("SEMVER", "ECOSYSTEM")]
    if not ranges:
        return False if versions else None
    try:
        for r in ranges:
            if _in_osv_range(ecosystem if r["type"] == "ECOSYSTEM" else "npm", version, r.get("events") or []):
                return True
    except VersionError:
        return None
    return False


def _in_osv_range(eco: str, version: str, events: list[dict]) -> bool:
    """OSV range semantics: sorted events; introduced opens, fixed/last_affected/limit close."""
    def vkey(ev):
        (kind, val), = [(k, v) for k, v in ev.items() if k in ("introduced", "fixed", "last_affected", "limit")]
        return kind, val

    parsed = []
    for ev in events:
        try:
            parsed.append(vkey(ev))
        except ValueError:
            continue
    affected = False
    # OSV spec: evaluate in order of version; "0" means from the beginning.
    def cmp_to(val):
        if val == "0":
            return 1  # version > "0" always
        return compare(eco, version, val)

    # Sort events by version (introduced "0" first) - required by spec for correctness.
    def sort_key(item):
        kind, val = item
        return val
    order = sorted(parsed, key=functools.cmp_to_key(
        lambda x, y: -1 if x[1] == "0" else (1 if y[1] == "0" else compare(eco, x[1], y[1]))))
    for kind, val in order:
        c = cmp_to(val)
        if kind == "introduced":
            if c >= 0:
                affected = True
        elif kind == "fixed":
            if c >= 0:
                affected = False
        elif kind == "last_affected":
            if c > 0:
                affected = False
        elif kind == "limit":
            if c >= 0:
                affected = False
    return affected


def osv_fixed_versions(ecosystem: str, version: str, affected: dict) -> list[str]:
    """Return `fixed` events that are greater than the installed version."""
    out = []
    for r in affected.get("ranges") or []:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        eco = ecosystem if r["type"] == "ECOSYSTEM" else "npm"
        for ev in r.get("events") or []:
            fx = ev.get("fixed")
            if fx:
                try:
                    if compare(eco, fx, version) > 0:
                        out.append(fx)
                except VersionError:
                    continue
    return sort_versions(ecosystem, list(dict.fromkeys(out)))


def describe_osv_ranges(affected: dict) -> list[str]:
    """Human-readable range strings, e.g. '>=0, <4.17.21'."""
    out = []
    for r in affected.get("ranges") or []:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        cur = []
        for ev in r.get("events") or []:
            if "introduced" in ev:
                if cur:
                    out.append(", ".join(cur))
                cur = [f">= {ev['introduced']}"]
            elif "fixed" in ev:
                cur.append(f"< {ev['fixed']}")
                out.append(", ".join(cur)); cur = []
            elif "last_affected" in ev:
                cur.append(f"<= {ev['last_affected']}")
                out.append(", ".join(cur)); cur = []
            elif "limit" in ev:
                cur.append(f"< {ev['limit']} (limit)")
                out.append(", ".join(cur)); cur = []
        if cur:
            out.append(", ".join(cur))
    if affected.get("versions") and not out:
        vs = affected["versions"]
        out.append("explicit versions: " + ", ".join(vs[:8]) + (" ..." if len(vs) > 8 else ""))
    return out


# --------------------------------------------------------------------------- npm ranges

class NpmRange:
    """A practical implementation of node-semver range syntax.

    Supports: exact, comparators (<, <=, >, >=, =), x-ranges (1.x, 1.2.*), tilde,
    caret, hyphen ranges, "*"/"latest"/"" and "||" unions. Prereleases only satisfy
    a comparator set if one of its comparators has the same [major, minor, patch]
    tuple with a prerelease (node-semver default behaviour).
    """

    def __init__(self, text: str):
        if text is None or len(text) > 512:
            raise VersionError("range too long")
        self.raw = text.strip()
        self.sets: list[list[tuple[str, SemVer]]] = []
        for part in self.raw.split("||"):
            self.sets.append(self._parse_set(part.strip()))

    @staticmethod
    def _xr(s: str):
        s = s.lstrip("v=").strip()
        if s in ("", "*", "x", "X", "latest"):
            return None, None, None, ()
        m = re.match(r"^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", s)
        if not m:
            raise VersionError(f"invalid npm range component: {s[:40]!r}")
        def n(x):
            return None if x is None or x in "xX*" else int(x)
        return n(m.group(1)), n(m.group(2)), n(m.group(3)), _pre_tuple(m.group(4))

    def _parse_set(self, part: str) -> list[tuple[str, SemVer]]:
        if part in ("", "*", "x", "X", "latest"):
            return [(">=", SemVer(0, 0, 0))]
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", part)
        if hy:
            lo = self._xr(hy.group(1)); hi = self._xr(hy.group(2))
            comps = [(">=", SemVer(lo[0] or 0, lo[1] or 0, lo[2] or 0, lo[3]))]
            if hi[0] is None:
                pass
            elif hi[1] is None:
                comps.append(("<", SemVer(hi[0] + 1, 0, 0, (0,))))
            elif hi[2] is None:
                comps.append(("<", SemVer(hi[0], hi[1] + 1, 0, (0,))))
            else:
                comps.append(("<=", SemVer(hi[0], hi[1], hi[2], hi[3])))
            return comps
        # normalise "> 1.2" -> ">1.2"
        part = re.sub(r"(<=|>=|<|>|=|\^|~>?)\s+", r"\1", part)
        comps: list[tuple[str, SemVer]] = []
        for tok in part.split():
            comps.extend(self._parse_comp(tok))
        return comps

    def _parse_comp(self, tok: str):
        m = re.match(r"^(<=|>=|<|>|=|\^|~>?|)(.*)$", tok)
        op, rest = m.group(1), m.group(2)
        M, mi, p, pre = self._xr(rest)
        Z = (0,)  # "-0": lowest possible prerelease, used for exclusive upper bounds
        if op == "^":
            if M is None:
                return [(">=", SemVer(0, 0, 0))]
            lo = SemVer(M, mi or 0, p or 0, pre)
            if M > 0 or mi is None:
                hi = SemVer(M + 1, 0, 0, Z)
            elif mi > 0 or p is None:
                hi = SemVer(0, mi + 1, 0, Z)
            else:
                hi = SemVer(0, 0, p + 1, Z)
            return [(">=", lo), ("<", hi)]
        if op.startswith("~"):
            if M is None:
                return [(">=", SemVer(0, 0, 0))]
            lo = SemVer(M, mi or 0, p or 0, pre)
            hi = SemVer(M + 1, 0, 0, Z) if mi is None else SemVer(M, mi + 1, 0, Z)
            return [(">=", lo), ("<", hi)]
        if M is None:
            return [(">=", SemVer(0, 0, 0))] if op in ("", "=", ">=", "<=") else [("<", SemVer(0, 0, 0, Z))]
        if mi is None or p is None:  # x-range
            lo = SemVer(M, mi or 0, 0)
            hi = SemVer(M + 1, 0, 0, Z) if mi is None else SemVer(M, mi + 1, 0, Z)
            if op in ("", "="):
                return [(">=", lo), ("<", hi)]
            if op == ">":
                return [(">=", hi)]
            if op == ">=":
                return [(">=", lo)]
            if op == "<":
                return [("<", lo)]
            if op == "<=":
                return [("<", hi)]
        v = SemVer(M, mi, p, pre)
        return [(op or "=", v)]

    def satisfied_by(self, version: str) -> bool:
        v = SemVer.parse(version)
        for comps in self.sets:
            if all(_test(op, v, c) for op, c in comps):
                if v.prerelease:
                    # prerelease allowed only if some comparator shares the tuple and has a prerelease
                    if not any(c.prerelease and c.prerelease != (0,) and (c.major, c.minor, c.patch) == (v.major, v.minor, v.patch)
                               for _, c in comps):
                        continue
                return True
        return False


def _test(op: str, v: SemVer, c: SemVer) -> bool:
    kv, kc = v.key(), c.key()
    return {"=": kv == kc, "<": kv < kc, "<=": kv <= kc, ">": kv > kc, ">=": kv >= kc}[op]


# --------------------------------------------------------------------------- generic spec satisfaction

def is_exact_spec(ecosystem: str, spec: Optional[str]) -> bool:
    if not spec:
        return False
    s = spec.strip()
    if ecosystem == "npm":
        return bool(_SEMVER_RE.match(s.lstrip("=")))
    if ecosystem == "PyPI":
        return bool(re.match(r"^===?\s*[^,*]+$", s)) and "*" not in s
    if ecosystem == "crates.io":
        return s.startswith("=")
    if ecosystem in ("Maven", "Go", "NuGet"):
        return not any(ch in s for ch in "[](),*+") and "$" not in s and s.lower() not in ("latest", "release")
    return False


def satisfies(ecosystem: str, version: str, spec: Optional[str]) -> Optional[bool]:
    """Does `version` satisfy the declared `spec`? None if it cannot be determined."""
    if spec is None:
        return None
    try:
        if ecosystem == "npm":
            if re.match(r"^(file:|link:|git|github:|http|npm:|workspace:)", spec.strip()) or "/" in spec:
                return None
            return NpmRange(spec).satisfied_by(version)
        if ecosystem == "PyPI":
            if not spec.strip():
                return True
            return SpecifierSet(spec).contains(Version(version), prereleases=True)
        if ecosystem == "crates.io":
            s = spec.strip()
            if not s:
                return True
            # cargo default requirement is caret
            parts = [p.strip() for p in s.split(",")]
            conv = [p if re.match(r"^[<>=~^*]", p) else "^" + p for p in parts]
            return NpmRange(" ".join(c.replace("=", "") if c.startswith("=") and not c.startswith("==") else c for c in conv)).satisfied_by(version)
        if ecosystem in ("Go", "NuGet", "Maven"):
            s = spec.strip()
            if ecosystem == "Maven" and s[:1] in "[(":
                return _maven_range(s, version)
            return compare(ecosystem, version, s) == 0
    except (VersionError, InvalidSpecifier, InvalidVersion):
        return None
    return None


def _maven_range(spec: str, version: str) -> Optional[bool]:
    m = re.match(r"^([\[(])\s*([^,]*)\s*(?:,\s*([^\])]*))?\s*([\])])$", spec)
    if not m:
        return None
    lo_inc, lo, hi, hi_inc = m.group(1) == "[", m.group(2).strip(), m.group(3), m.group(4) == "]"
    if hi is None:  # [1.0] exact
        return compare("Maven", version, lo) == 0
    hi = hi.strip()
    if lo:
        c = compare("Maven", version, lo)
        if c < 0 or (c == 0 and not lo_inc):
            return False
    if hi:
        c = compare("Maven", version, hi)
        if c > 0 or (c == 0 and not hi_inc):
            return False
    return True
