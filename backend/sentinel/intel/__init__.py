"""Intelligence providers with a shared cache / provenance model.

Every lookup returns data plus *where it came from*: `live`, `cache` (fresh), `stale`
(older than TTL, used because the live call failed), or `fixture` (versioned demo snapshot).
When nothing is available the result is `unavailable` — never an empty "clean" answer.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .. import db
from ..config import CACHE_TTL_SECONDS
from .http import ProviderError, RequestBlocked


@dataclass
class ProviderStatus:
    name: str
    label: str
    purpose: str
    data_sent: str
    status: str = "not_used"          # ok | degraded | failed | offline | disabled | not_used
    live_calls: int = 0
    cache_hits: int = 0
    stale_hits: int = 0
    fixture_hits: int = 0
    misses: int = 0
    errors: list = field(default_factory=list)
    oldest_data: Optional[float] = None
    newest_data: Optional[float] = None

    def note_data(self, ts: float):
        self.oldest_data = ts if self.oldest_data is None else min(self.oldest_data, ts)
        self.newest_data = ts if self.newest_data is None else max(self.newest_data, ts)

    def error(self, msg: str):
        if len(self.errors) < 10 and msg not in self.errors:
            self.errors.append(msg)

    def finalize(self):
        if self.status in ("offline", "disabled"):
            return
        used = self.live_calls + self.cache_hits + self.stale_hits + self.fixture_hits
        if self.misses and not used:
            self.status = "failed"
        elif self.misses or self.stale_hits or self.errors:
            self.status = "degraded"
        elif used:
            self.status = "ok"

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return d


class IntelContext:
    """Per-scan provider state: offline flag, cancellation, provenance counters."""

    def __init__(self, offline: bool = False, cancel_event: Optional[threading.Event] = None,
                 enable_registry: bool = True, enable_scorecard: bool = True, enable_epss_kev: bool = True):
        self.offline = offline
        self.cancel_event = cancel_event or threading.Event()
        self.enable_registry = enable_registry
        self.enable_scorecard = enable_scorecard
        self.enable_epss_kev = enable_epss_kev
        self._lock = threading.Lock()
        self.providers: dict[str, ProviderStatus] = {
            "osv": ProviderStatus("osv", "OSV.dev", "Version-specific vulnerability matching and advisory details",
                                  "Package ecosystem, name and exact version; advisory IDs"),
            "npm": ProviderStatus("npm", "npm registry", "Package metadata: publish dates, maintainers, scripts, provenance, versions",
                                  "Package names"),
            "pypi": ProviderStatus("pypi", "PyPI JSON API", "Package metadata: release dates, versions, project URLs",
                                   "Package names"),
            "scorecard": ProviderStatus("scorecard", "OpenSSF Scorecard", "Source repository security posture",
                                        "Public GitHub repository paths of dependencies"),
            "kev": ProviderStatus("kev", "CISA KEV catalog", "Known exploitation in the wild (CVE list)",
                                  "Nothing (whole catalog downloaded)"),
            "epss": ProviderStatus("epss", "FIRST EPSS", "Exploit prediction probability for CVEs", "CVE identifiers"),
        }
        if offline:
            for p in self.providers.values():
                p.status = "offline"
        if not enable_registry:
            self.providers["npm"].status = self.providers["pypi"].status = "disabled"
        if not enable_scorecard:
            self.providers["scorecard"].status = "disabled"
        if not enable_epss_kev:
            self.providers["kev"].status = self.providers["epss"].status = "disabled"

    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def lookup(self, provider: str, key: str, fetch: Callable[[], Any], ttl_key: Optional[str] = None) -> tuple[Any, str, Optional[float]]:
        """Cache-first lookup. Returns (value, origin, fetched_at); origin 'unavailable' when nothing found."""
        st = self.providers[provider]
        ttl = CACHE_TTL_SECONDS.get(ttl_key or provider, 3600)
        hit = db.cache_get(key, None)
        if hit is not None:
            value, ts, origin = hit
            fresh = (time.time() - ts) <= ttl
            if origin == "fixture":
                # Fixture data is only served offline, or as a fallback when the live call fails.
                if self.offline:
                    with self._lock:
                        st.fixture_hits += 1
                        st.note_data(ts)
                    return value, "fixture", ts
            elif fresh or self.offline:
                with self._lock:
                    st.cache_hits += 1
                    st.note_data(ts)
                return value, "cache", ts
        if self.offline or st.status == "disabled":
            with self._lock:
                st.misses += 1
            return None, "unavailable", None
        try:
            value = fetch()
            now = time.time()
            db.cache_put(key, provider, value, "live", now)
            with self._lock:
                st.live_calls += 1
                st.note_data(now)
            return value, "live", now
        except (ProviderError, RequestBlocked) as exc:
            with self._lock:
                st.error(str(exc))
            if hit is not None:
                value, ts, origin = hit
                with self._lock:
                    if origin == "fixture":
                        st.fixture_hits += 1
                    else:
                        st.stale_hits += 1
                    st.note_data(ts)
                return value, ("fixture" if origin == "fixture" else "stale"), ts
            with self._lock:
                st.misses += 1
            return None, "unavailable", None

    def provider_summary(self) -> list[dict]:
        out = []
        for p in self.providers.values():
            p.finalize()
            out.append(p.to_dict())
        return out


def load_fixture(path: Path) -> dict:
    """Import a versioned intelligence snapshot into the cache with origin='fixture'."""
    data = json.loads(path.read_text(encoding="utf-8"))
    n = 0
    for key, entry in (data.get("entries") or {}).items():
        db.cache_put(key, entry["provider"], entry["value"], "fixture", entry["fetched_at"])
        n += 1
    return {"entries": n, "snapshot_created": data.get("created_at"), "description": data.get("description")}
