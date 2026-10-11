"""SQLite persistence: scan history, intelligence cache, settings, security event log.

All queries are parameterised. Connections are per-thread.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .config import DATA_DIR

_local = threading.local()
_lock = threading.Lock()
_db_path: Optional[Path] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL,
    source_name TEXT,
    source_kind TEXT,
    content_hash TEXT,
    is_demo INTEGER DEFAULT 0,
    summary_json TEXT,
    result_json TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at);
CREATE TABLE IF NOT EXISTS intel_cache (
    key TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    origin TEXT NOT NULL,
    value_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT
);
"""


def init(path: Optional[Path] = None):
    global _db_path
    with _lock:
        _db_path = Path(path) if path else DATA_DIR / "sentinel.db"
        _db_path.parent.mkdir(parents=True, exist_ok=True)
        _local.__dict__.pop("conn", None)
        conn = sqlite3.connect(_db_path)
        conn.executescript(SCHEMA)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()
        conn.close()


def conn() -> sqlite3.Connection:
    if _db_path is None:
        init()
    c = getattr(_local, "conn", None)
    if c is None or getattr(_local, "path", None) != _db_path:
        c = sqlite3.connect(_db_path, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        _local.conn, _local.path = c, _db_path
    return c


# ------------------------------------------------------------------ cache

def cache_get(key: str, max_age: Optional[float]) -> Optional[tuple[Any, float, str]]:
    row = conn().execute("SELECT value_json, fetched_at, origin FROM intel_cache WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    if max_age is not None and time.time() - row["fetched_at"] > max_age:
        return None
    return json.loads(row["value_json"]), row["fetched_at"], row["origin"]


def cache_put(key: str, provider: str, value: Any, origin: str = "live", fetched_at: Optional[float] = None):
    c = conn()
    c.execute("INSERT OR REPLACE INTO intel_cache(key, provider, fetched_at, origin, value_json) VALUES (?,?,?,?,?)",
              (key, provider, fetched_at or time.time(), origin, json.dumps(value, separators=(",", ":"))))
    c.commit()


def cache_stats() -> list[dict]:
    rows = conn().execute("SELECT provider, origin, COUNT(*) n, MIN(fetched_at) oldest, MAX(fetched_at) newest "
                          "FROM intel_cache GROUP BY provider, origin").fetchall()
    return [dict(r) for r in rows]


def cache_clear(origin: Optional[str] = None):
    c = conn()
    if origin:
        c.execute("DELETE FROM intel_cache WHERE origin=?", (origin,))
    else:
        c.execute("DELETE FROM intel_cache")
    c.commit()


# ------------------------------------------------------------------ settings

DEFAULT_SETTINGS = {
    "offline_mode": False,
    "retention_days": 30,
    "enable_registry_metadata": True,
    "enable_scorecard": True,
    "enable_epss_kev": True,
    "policy": None,  # filled from policy.DEFAULT_POLICY on first read
}


def get_settings() -> dict:
    out = dict(DEFAULT_SETTINGS)
    for row in conn().execute("SELECT key, value_json FROM settings").fetchall():
        out[row["key"]] = json.loads(row["value_json"])
    return out


def put_setting(key: str, value: Any):
    c = conn()
    c.execute("INSERT OR REPLACE INTO settings(key, value_json) VALUES (?,?)", (key, json.dumps(value)))
    c.commit()


# ------------------------------------------------------------------ scans

def scan_insert(scan_id: str, source_name: str, source_kind: str, content_hash: str, is_demo: bool):
    c = conn()
    c.execute("INSERT INTO scans(id, created_at, status, source_name, source_kind, content_hash, is_demo) VALUES (?,?,?,?,?,?,?)",
              (scan_id, time.time(), "queued", source_name, source_kind, content_hash, int(is_demo)))
    c.commit()


def scan_update(scan_id: str, **fields):
    allowed = {"status", "finished_at", "summary_json", "result_json", "error"}
    keys = [k for k in fields if k in allowed]
    if not keys:
        return
    sql = "UPDATE scans SET " + ", ".join(f"{k}=?" for k in keys) + " WHERE id=?"
    c = conn()
    c.execute(sql, [fields[k] for k in keys] + [scan_id])
    c.commit()


def scan_get(scan_id: str, with_result: bool = False) -> Optional[dict]:
    cols = "id, created_at, finished_at, status, source_name, source_kind, content_hash, is_demo, summary_json, error"
    if with_result:
        cols += ", result_json"
    row = conn().execute(f"SELECT {cols} FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def scan_list(limit: int = 50, offset: int = 0) -> list[dict]:
    rows = conn().execute("SELECT id, created_at, finished_at, status, source_name, source_kind, is_demo, summary_json, error "
                          "FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    return [dict(r) for r in rows]


def scan_delete(scan_id: str) -> bool:
    c = conn()
    cur = c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    c.commit()
    return cur.rowcount > 0


def scan_purge(older_than_days: Optional[float] = None, demo_only: bool = False) -> int:
    c = conn()
    clauses, params = [], []
    if older_than_days is not None:
        clauses.append("created_at < ?")
        params.append(time.time() - older_than_days * 86400)
    if demo_only:
        clauses.append("is_demo = 1")
    sql = "DELETE FROM scans" + (" WHERE " + " AND ".join(clauses) if clauses else "")
    cur = c.execute(sql, params)
    c.commit()
    return cur.rowcount


def scan_find_running(content_hash: str) -> Optional[str]:
    row = conn().execute("SELECT id FROM scans WHERE content_hash=? AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1",
                         (content_hash,)).fetchone()
    return row["id"] if row else None


def mark_interrupted():
    c = conn()
    c.execute("UPDATE scans SET status='failed', error='Interrupted by server restart' WHERE status IN ('queued','running')")
    c.commit()


# ------------------------------------------------------------------ security events

def log_event(kind: str, detail: str = ""):
    """Record a security-relevant event. Callers must not pass secrets or file contents."""
    c = conn()
    c.execute("INSERT INTO events(ts, kind, detail) VALUES (?,?,?)", (time.time(), kind[:64], detail[:300]))
    c.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)")
    c.commit()


def recent_events(limit: int = 100) -> list[dict]:
    rows = conn().execute("SELECT ts, kind, detail FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
