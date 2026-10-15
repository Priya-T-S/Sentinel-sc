"""Hardened outbound HTTP client.

* HTTPS only, TLS verification always on.
* Destination host must be in the fixed provider allow-list (no user-supplied URLs).
* Redirects are not followed automatically; a redirect is only honoured when it stays on
  an allow-listed HTTPS host (re-validated each hop, max 3).
* Responses are streamed and capped in size; timeouts on connect and read.
* Bounded retries with exponential backoff for 429/5xx and transport errors.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from ..config import ALLOWED_HOSTS, LIMITS, USER_AGENT


class ProviderError(RuntimeError):
    """A provider could not be reached or returned an unusable response."""

    def __init__(self, message: str = "", status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class RequestBlocked(ProviderError):
    """The request violated the egress policy (non-allow-listed host, insecure scheme...)."""


def check_url(url: str) -> str:
    p = urlparse(url)
    if p.scheme != "https":
        raise RequestBlocked("only https is permitted")
    host = (p.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise RequestBlocked("destination host is not an allow-listed intelligence provider")
    if p.username or p.password or (p.port not in (None, 443)):
        raise RequestBlocked("credentials or non-standard ports are not permitted")
    return url


_client: Optional[httpx.Client] = None


def client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(
            timeout=httpx.Timeout(LIMITS.http_timeout_seconds, connect=8.0),
            follow_redirects=False, verify=True, http2=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
        )
    return _client


def _request(method: str, url: str, *, body: Any, headers: Optional[dict], max_bytes: int,
             retries: int, parse) -> Any:
    """Shared hardened request loop. `parse(bytes)` turns the capped body into the result."""
    attempt = 0
    last_exc: Optional[Exception] = None
    while attempt <= retries:
        attempt += 1
        current = check_url(url)
        try:
            for _hop in range(4):
                with client().stream(method, current, json=body, headers=headers) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        nxt = httpx.URL(current).join(loc)
                        current = check_url(str(nxt))  # re-validate every redirect hop
                        continue
                    if resp.status_code == 404:
                        return None
                    if resp.status_code == 429 or resp.status_code >= 500:
                        raise ProviderError(f"provider returned HTTP {resp.status_code}", resp.status_code)
                    if resp.status_code >= 400:
                        raise ProviderError(f"provider rejected request (HTTP {resp.status_code})", resp.status_code)
                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise ProviderError("provider response exceeds size limit")
                    buf = bytearray()
                    for chunk in resp.iter_bytes():
                        buf.extend(chunk)
                        if len(buf) > max_bytes:
                            raise ProviderError("provider response exceeds size limit")
                    return parse(bytes(buf))
            raise ProviderError("too many redirects")
        except RequestBlocked:
            raise
        except ProviderError as exc:
            last_exc = exc
            if "size limit" in str(exc) or "rejected" in str(exc) or "malformed" in str(exc):
                break
        except httpx.HTTPError as exc:
            last_exc = ProviderError(f"network error: {type(exc).__name__}")
        if attempt <= retries:
            time.sleep(min(0.5 * (2 ** (attempt - 1)), 4.0))
    raise last_exc or ProviderError("request failed")


def _parse_json(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProviderError("provider returned malformed JSON") from exc


def request_json(method: str, url: str, *, body: Any = None, headers: Optional[dict] = None,
                 max_bytes: Optional[int] = None, retries: Optional[int] = None) -> Any:
    """JSON request through the hardened client. Returns None on 404."""
    return _request(method, url, body=body, headers=headers, max_bytes=max_bytes or LIMITS.http_max_response_bytes,
                    retries=LIMITS.http_retries if retries is None else retries, parse=_parse_json)


def request_bytes(url: str, *, max_bytes: int, headers: Optional[dict] = None, retries: int = 1) -> Optional[bytes]:
    """Binary GET (e.g. a repository archive) with the same egress, redirect and size controls."""
    return _request("GET", url, body=None, headers=headers, max_bytes=max_bytes, retries=retries, parse=lambda b: b)
