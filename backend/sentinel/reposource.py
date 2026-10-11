"""Bounded, read-only access to the repository under scan.

Two implementations share one interface:

* `ZipSource`  - an uploaded .zip. Members are read in memory; nothing is extracted to disk,
                 so path-traversal and symlink entries can never write outside a sandbox.
                 Unsafe entries are rejected and recorded.
* `DirSource`  - a local directory (CLI). Symlinks are never followed and every resolved path
                 must stay inside the root.

Both enforce file-count, per-file size, total-bytes, path-depth and decompression-ratio limits.
"""
from __future__ import annotations

import io
import os
import posixpath
import stat
import zipfile
from dataclasses import dataclass, field
from typing import Optional

from .config import LIMITS


class UnsafeInputError(ValueError):
    """Input rejected by a safety control. Message is safe to show to users."""


@dataclass
class SourceReport:
    files_seen: int = 0
    rejected: list = field(default_factory=list)  # [{"path": str, "reason": str}]
    skipped_large: int = 0
    bytes_read: int = 0

    def reject(self, path: str, reason: str):
        if len(self.rejected) < 200:
            self.rejected.append({"path": _safe_display(path), "reason": reason})


def _safe_display(path: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in path)
    return cleaned[:200]


def normalize_member(name: str) -> Optional[str]:
    """Return a safe, normalised relative POSIX path, or None if the name is unsafe."""
    if not name or "\x00" in name or len(name) > LIMITS.max_path_length:
        return None
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) > 1 and n[1] == ":"):  # absolute / drive letter
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    if len(parts) > LIMITS.max_path_depth:
        return None
    return "/".join(parts)


class RepoSource:
    name: str = "repository"
    report: SourceReport

    def list_files(self) -> list[str]:
        raise NotImplementedError

    def read_bytes(self, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        raise NotImplementedError

    def read_text(self, path: str, max_bytes: Optional[int] = None) -> Optional[str]:
        data = self.read_bytes(path, max_bytes)
        if data is None:
            return None
        if b"\x00" in data[:4096]:
            return None  # binary
        return data.decode("utf-8", errors="replace")

    def exists(self, path: str) -> bool:
        return path in self._index()

    def _index(self) -> set:
        raise NotImplementedError


class ZipSource(RepoSource):
    def __init__(self, data: bytes, name: str = "upload.zip"):
        if len(data) > LIMITS.max_upload_bytes:
            raise UnsafeInputError("Archive exceeds the maximum upload size.")
        self.name = name
        self.report = SourceReport()
        try:
            self._zf = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            raise UnsafeInputError("File is not a valid ZIP archive.") from exc
        self._members: dict[str, zipfile.ZipInfo] = {}
        self._total_read = 0
        infos = self._zf.infolist()
        if len(infos) > LIMITS.max_archive_entries:
            raise UnsafeInputError(f"Archive has more than {LIMITS.max_archive_entries} entries.")
        declared_total = 0
        for info in infos:
            if info.is_dir():
                continue
            norm = normalize_member(info.filename)
            if norm is None:
                self.report.reject(info.filename, "unsafe path (absolute, traversal, or too deep)")
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                self.report.reject(info.filename, "symbolic link entries are not followed")
                continue
            if info.flag_bits & 0x1:
                self.report.reject(info.filename, "encrypted entry")
                continue
            if info.compress_size > 0 and info.file_size / max(info.compress_size, 1) > LIMITS.max_compression_ratio \
                    and info.file_size > 1_000_000:
                self.report.reject(info.filename, "suspicious compression ratio (possible decompression bomb)")
                continue
            declared_total += info.file_size
            if norm in self._members:
                self.report.reject(info.filename, "duplicate entry name")
                continue
            self._members[norm] = info
        if declared_total > LIMITS.max_uncompressed_bytes * 4:
            raise UnsafeInputError("Archive declares an excessive uncompressed size (possible decompression bomb).")
        self._strip_single_top_dir()
        self.report.files_seen = len(self._members)

    def _strip_single_top_dir(self):
        """GitHub-style archives wrap everything in one top-level folder; strip it."""
        tops = {p.split("/", 1)[0] for p in self._members}
        if len(tops) == 1 and all("/" in p for p in self._members) and not next(iter(tops)).startswith("."):
            top = next(iter(tops)) + "/"
            self._members = {p[len(top):]: i for p, i in self._members.items()}

    def _index(self) -> set:
        return set(self._members)

    def list_files(self) -> list[str]:
        return sorted(self._members)

    def read_bytes(self, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        info = self._members.get(path)
        if info is None:
            return None
        cap = min(max_bytes or LIMITS.max_file_bytes, LIMITS.max_file_bytes)
        if info.file_size > cap:
            self.report.skipped_large += 1
            return None
        if self._total_read + cap > LIMITS.max_uncompressed_bytes and self._total_read + info.file_size > LIMITS.max_uncompressed_bytes:
            raise UnsafeInputError("Total extracted data exceeds the configured limit.")
        # Never trust header sizes: read at most cap+1 bytes from the stream.
        with self._zf.open(info) as fh:
            data = fh.read(cap + 1)
        if len(data) > cap:
            self.report.reject(path, "actual size exceeds declared size / limit")
            return None
        self._total_read += len(data)
        self.report.bytes_read = self._total_read
        return data


class DirSource(RepoSource):
    def __init__(self, root: str):
        real = os.path.realpath(root)
        if not os.path.isdir(real):
            raise UnsafeInputError("Path is not a directory.")
        self.root = real
        self.name = os.path.basename(real) or "repository"
        self.report = SourceReport()
        self._files: list[str] = []
        self._walk()

    def _walk(self):
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, self.root)
            depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
            # prune VCS and very deep dirs; node_modules kept but bounded by file-count
            dirnames[:] = [d for d in dirnames if d not in (".git", ".hg", ".svn", "__pycache__", ".venv", "venv")
                           and not os.path.islink(os.path.join(dirpath, d))]
            if depth >= LIMITS.max_path_depth:
                dirnames[:] = []
                continue
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if os.path.islink(full):
                    self.report.reject(os.path.relpath(full, self.root), "symbolic link not followed")
                    continue
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                count += 1
                if count > LIMITS.max_archive_entries:
                    raise UnsafeInputError(f"Directory has more than {LIMITS.max_archive_entries} files.")
                self._files.append(rel)
        self.report.files_seen = len(self._files)
        self._set = set(self._files)

    def _index(self) -> set:
        return self._set

    def list_files(self) -> list[str]:
        return sorted(self._files)

    def read_bytes(self, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        if path not in self._set:
            return None
        full = os.path.realpath(os.path.join(self.root, path))
        if os.path.commonpath([full, self.root]) != self.root:
            self.report.reject(path, "resolved outside repository root")
            return None
        cap = min(max_bytes or LIMITS.max_file_bytes, LIMITS.max_file_bytes)
        try:
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size > cap:
                self.report.skipped_large += 1
                return None
            with open(full, "rb") as fh:
                data = fh.read(cap + 1)
        except OSError:
            return None
        if len(data) > cap:
            return None
        self.report.bytes_read += len(data)
        return data


class SingleFileSource(RepoSource):
    """A single uploaded manifest/lockfile/SBOM."""

    def __init__(self, filename: str, data: bytes):
        norm = normalize_member(os.path.basename(filename.replace("\\", "/")))
        if not norm:
            raise UnsafeInputError("Unsafe file name.")
        if len(data) > LIMITS.max_file_bytes:
            raise UnsafeInputError("File exceeds the maximum size.")
        self.name = norm
        self._data = {norm: data}
        self.report = SourceReport(files_seen=1, bytes_read=len(data))

    def _index(self) -> set:
        return set(self._data)

    def list_files(self) -> list[str]:
        return list(self._data)

    def read_bytes(self, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        return self._data.get(path)


def basename(path: str) -> str:
    return posixpath.basename(path)


def dirname(path: str) -> str:
    return posixpath.dirname(path)
