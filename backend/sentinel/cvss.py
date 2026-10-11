"""CVSS v3.0/v3.1 base score calculation from a vector string (FIRST specification).

OSV publishes CVSS *vectors*; the numeric base score is derived here with the official
formula. CVSS v4 vectors are not scored locally (the formula requires the full MacroVector
lookup table); for v4-only advisories the source's qualitative severity is used instead.
"""
from __future__ import annotations

import math
from typing import Optional

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score_v3(vector: str) -> Optional[float]:
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")) or len(vector) > 200:
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        s = m["S"]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        if s == "U":
            impact = 6.42 * iss
        elif s == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            return None
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[s][m["PR"]] * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if s == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def network_exploitable(vector: Optional[str]) -> Optional[bool]:
    if not vector or "AV:" not in vector:
        return None
    return "AV:N" in vector
