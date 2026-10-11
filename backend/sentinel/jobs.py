"""Bounded background scan execution with progress, cancellation and duplicate suppression."""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from . import db, engine
from .config import LIMITS
from .reposource import RepoSource

log = logging.getLogger("sentinel.jobs")


class QueueFull(RuntimeError):
    pass


class JobManager:
    def __init__(self):
        self._pool = ThreadPoolExecutor(max_workers=LIMITS.max_concurrent_scans, thread_name_prefix="scan")
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._results: "OrderedDict[str, dict]" = OrderedDict()

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j["status"] in ("queued", "running"))

    def submit(self, make_source: Callable[[], RepoSource], *, source_name: str, source_kind: str, content_key: bytes,
               offline: bool, is_demo: bool = False) -> tuple[str, bool]:
        """Returns (scan_id, deduplicated)."""
        h = hashlib.sha256(content_key + (b"|offline" if offline else b"|online")).hexdigest()
        existing = db.scan_find_running(h)
        if existing and existing in self._jobs:
            return existing, True
        if self.active_count() >= LIMITS.max_queued_scans:
            raise QueueFull("Too many scans in progress. Try again shortly.")
        scan_id = uuid.uuid4().hex[:16]
        db.scan_insert(scan_id, source_name[:200], source_kind, h, is_demo)
        cancel = threading.Event()
        with self._lock:
            self._jobs[scan_id] = {"status": "queued", "progress": {"percent": 0, "stage": None, "stages": []},
                                   "cancel": cancel, "created": time.time()}
        self._pool.submit(self._run, scan_id, make_source, offline, cancel)
        return scan_id, False

    def _run(self, scan_id: str, make_source, offline: bool, cancel: threading.Event):
        job = self._jobs[scan_id]
        if cancel.is_set():
            job["status"] = "cancelled"
            db.scan_update(scan_id, status="cancelled", finished_at=time.time())
            return
        job["status"] = "running"
        db.scan_update(scan_id, status="running")
        timer = threading.Timer(LIMITS.scan_timeout_seconds, cancel.set)
        timer.daemon = True
        timer.start()
        try:
            src = make_source()

            def on_progress(p):
                job["progress"] = p
            settings = db.get_settings()
            result = engine.run_scan(src, offline=offline or bool(settings.get("offline_mode")), progress_cb=on_progress,
                                     cancel=cancel, settings=settings, scan_id=scan_id)
            status = "failed" if result["scan"]["status"] == "failed" else "completed"
            db.scan_update(scan_id, status=status, finished_at=time.time(), summary_json=json.dumps(_brief(result)),
                           result_json=json.dumps(result, separators=(",", ":")),
                           error=result["scan"].get("fatal_error") or ("No supported manifests found." if status == "failed" else None))
            job["status"] = status
            self._remember(scan_id, result)
        except engine.ScanCancelled:
            job["status"] = "cancelled"
            db.scan_update(scan_id, status="cancelled", finished_at=time.time(),
                           error="Cancelled" + (" (time limit reached)" if not job.get("user_cancel") else ""))
        except Exception as exc:  # never leak internals to clients
            ref = uuid.uuid4().hex[:8]
            log.exception("scan %s failed (ref %s)", scan_id, ref)
            msg = str(exc) if exc.__class__.__name__ in ("UnsafeInputError", "ManifestError") else f"Internal scan error (ref {ref})."
            job["status"] = "failed"
            db.scan_update(scan_id, status="failed", finished_at=time.time(), error=msg)
            db.log_event("scan_failed", f"scan={scan_id} ref={ref} type={exc.__class__.__name__}")
        finally:
            timer.cancel()
            retention = db.get_settings().get("retention_days")
            if isinstance(retention, (int, float)) and retention > 0:
                db.scan_purge(older_than_days=retention)

    def cancel(self, scan_id: str) -> bool:
        job = self._jobs.get(scan_id)
        if not job or job["status"] not in ("queued", "running"):
            return False
        job["user_cancel"] = True
        job["cancel"].set()
        return True

    def status(self, scan_id: str) -> Optional[dict]:
        job = self._jobs.get(scan_id)
        if not job:
            return None
        return {"status": job["status"], "progress": job["progress"]}

    def _remember(self, scan_id: str, result: dict):
        with self._lock:
            self._results[scan_id] = result
            self._results.move_to_end(scan_id)
            while len(self._results) > 6:
                self._results.popitem(last=False)

    def result(self, scan_id: str) -> Optional[dict]:
        with self._lock:
            if scan_id in self._results:
                self._results.move_to_end(scan_id)
                return self._results[scan_id]
        row = db.scan_get(scan_id, with_result=True)
        if not row or not row.get("result_json"):
            return None
        res = json.loads(row["result_json"])
        self._remember(scan_id, res)
        return res

    def forget(self, scan_id: str):
        with self._lock:
            self._results.pop(scan_id, None)
            self._jobs.pop(scan_id, None)


def _brief(result: dict) -> dict:
    s = result["summary"]
    return {"status": s["status"], "packages": s["packages"], "direct": s["direct"], "vulnerabilities": s["vulnerabilities"],
            "vulnerable_packages": s["vulnerable_packages"], "severity": s["severity"], "suspicious_signals": s["suspicious_signals"],
            "unverified_packages": s["unverified_packages"], "policy": result["policy"]["verdict"], "max_priority": s["max_priority"],
            "ecosystems": list(s["by_ecosystem"].keys()), "offline": result["scan"]["offline"],
            "findings": len(result["findings"])}
