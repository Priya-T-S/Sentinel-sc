"""Shared parser types and helpers."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import DependencyGraph, Root


class ManifestError(ValueError):
    """A manifest was malformed. Message must be safe for display (no file contents)."""


@dataclass
class ParseOutcome:
    file: str
    ecosystem: str
    kind: str                 # "manifest" | "lockfile" | "sbom"
    parser: str
    status: str               # "parsed" | "partial" | "unsupported" | "error" | "skipped"
    packages: int = 0
    message: str = ""
    limitations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ParseContext:
    graph: DependencyGraph
    outcomes: list = field(default_factory=list)
    # repo-level facts gathered while parsing, used by heuristics
    registries: list = field(default_factory=list)         # [{"file","scope","url","kind"}]
    drift: list = field(default_factory=list)              # [{"file","name","declared","locked","ecosystem"}]
    unpinned: list = field(default_factory=list)           # [{"file","name","spec","ecosystem","reason"}]
    missing_lockfiles: list = field(default_factory=list)  # [{"manifest","ecosystem"}]
    declared: dict = field(default_factory=dict)           # root_id -> {name: spec}


def load_json(text: str, file: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError(f"{file}: invalid JSON") from exc


def root_id(ecosystem: str, directory: str, name: Optional[str] = None) -> str:
    label = directory or "."
    return f"root:{ecosystem}:{label}" + (f":{name}" if name else "")


def make_root(ctx: ParseContext, ecosystem: str, directory: str, name: str, manifest: str,
              lockfile: Optional[str] = None, sub: Optional[str] = None) -> Root:
    rid = root_id(ecosystem, directory, sub)
    r = ctx.graph.add_root(Root(id=rid, name=name or (directory or "app"), ecosystem=ecosystem,
                                manifest=manifest, lockfile=lockfile))
    if lockfile and not r.lockfile:
        r.lockfile = lockfile
    return r


_SAFE_NAME = re.compile(r"^[A-Za-z0-9@._/+:~\-]{1,214}$")


def safe_name(name: Any) -> Optional[str]:
    """Package names come from untrusted input: accept only a conservative charset."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not _SAFE_NAME.match(name) or name.startswith("/") or any(seg in ("..", ".") for seg in re.split(r"[/:]", name)):
        return None
    return name


def safe_version(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    v = v.strip()
    if not v or len(v) > 128 or any(ch.isspace() for ch in v) or not v.isprintable():
        return None
    return v


def norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
