"""Import a PUBLIC GitHub repository by URL, safely.

What happens:
  1. The user's text is parsed into (owner, repo, ref). It must name github.com; nothing else is
     ever fetched from the user's text - we build every URL ourselves from validated parts.
  2. api.github.com tells us the default branch (if no ref given) and the exact commit SHA.
  3. The archive for THAT commit is downloaded from codeload.github.com with the hardened client:
     HTTPS only, allow-listed hosts, every redirect re-validated, size-capped while streaming.
  4. The bytes go through the normal in-memory ZipSource checks (traversal, symlinks, bombs).

Nothing is cloned, checked out to disk, installed or executed. The scanned commit SHA is recorded
in the result so the scan is reproducible.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, unquote, urlparse

from .config import LIMITS
from .intel.http import ProviderError, RequestBlocked, request_bytes, request_json
from .reposource import UnsafeInputError, ZipSource

_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class GitHubImportError(ValueError):
    """User-facing error (safe to display)."""


@dataclass
class GitHubRef:
    owner: str
    repo: str
    ref: Optional[str] = None

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_github_url(text: str) -> GitHubRef:
    """Accepts: https://github.com/o/r, github.com/o/r, o/r, .../tree/<ref>, .../commit/<sha>, o/r@<ref>, '.git' suffix."""
    if not isinstance(text, str):
        raise GitHubImportError("Enter a GitHub repository URL.")
    t = text.strip()
    if not t or len(t) > 400 or any(ch.isspace() or ord(ch) < 32 for ch in t):
        raise GitHubImportError("Enter a GitHub repository URL such as https://github.com/owner/repo.")
    ref = None
    if "://" in t or t.lower().startswith(("github.com/", "www.github.com/")):
        u = urlparse(t if "://" in t else "https://" + t)
        if u.scheme not in ("https", "http"):
            raise GitHubImportError("Only https://github.com URLs are supported.")
        if u.username or u.password or u.port not in (None, 443, 80):
            raise GitHubImportError("URLs with credentials or custom ports are not allowed.")
        if (u.hostname or "").lower() not in ("github.com", "www.github.com"):
            raise GitHubImportError("Only public repositories on github.com are supported.")
        if u.query or u.fragment:
            pass  # ignored: we never forward the user's URL
        parts = [unquote(p) for p in u.path.split("/") if p]
    else:
        if "@" in t:
            t, ref = t.rsplit("@", 1)
        parts = [p for p in t.split("/") if p]
    if len(parts) < 2:
        raise GitHubImportError("The URL must include both owner and repository, e.g. github.com/owner/repo.")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if len(parts) >= 4 and parts[2] in ("tree", "commit", "releases") and ref is None:
        ref = "/".join(parts[4:] if parts[2] == "releases" and parts[3] == "tag" else parts[3:])
    elif len(parts) > 2 and ref is None and parts[2] not in ("tree", "commit"):
        pass  # e.g. /issues or /blob/...: ignore the rest, scan default branch
    if not _OWNER.match(owner) or not _REPO.match(repo) or repo in (".", ".."):
        raise GitHubImportError("That does not look like a valid GitHub owner/repository name.")
    if ref is not None:
        if not _REF.match(ref) or ".." in ref or ref.startswith(("/", "-")) or ref.endswith("/"):
            raise GitHubImportError("Invalid branch, tag or commit name.")
    return GitHubRef(owner, repo, ref or None)


def _api(path: str) -> Optional[dict]:
    try:
        return request_json("GET", f"https://api.github.com{path}",
                            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
                            max_bytes=2 * 1024 * 1024, retries=1)
    except ProviderError as exc:
        if exc.status in (403, 429):
            raise GitHubImportError("GitHub's anonymous rate limit was reached (60 requests/hour). Try again later, "
                                    "or download the repository ZIP and upload it.") from exc
        raise GitHubImportError("Could not reach GitHub. Check your connection, or upload a ZIP instead.") from exc


def fetch_repository(ref: GitHubRef, progress=None) -> tuple[ZipSource, dict]:
    """Resolve to an exact commit, download its archive, return (ZipSource, provenance metadata)."""
    def step(msg):
        if progress:
            progress(msg)
    try:
        step("Looking up repository on GitHub")
        meta = _api(f"/repos/{quote(ref.owner)}/{quote(ref.repo)}")
        if not meta:
            raise GitHubImportError(f"Repository {ref.slug} was not found, or it is private. Only public repositories can be scanned by URL.")
        if meta.get("private"):
            raise GitHubImportError("Private repositories are not supported.")
        size_kb = meta.get("size") or 0
        # GitHub's 'size' is the full git history; it is only an early, generous sanity check.
        if isinstance(size_kb, int) and size_kb * 1024 > LIMITS.max_upload_bytes * 20:
            raise GitHubImportError("Repository is too large to scan by URL. Upload a ZIP of the relevant folder instead.")
        wanted = ref.ref or meta.get("default_branch") or "main"
        step(f"Resolving '{wanted}' to an exact commit")
        if _SHA.match(wanted):
            sha = wanted
            c = _api(f"/repos/{quote(ref.owner)}/{quote(ref.repo)}/commits/{sha}")
            if not c:
                raise GitHubImportError(f"Commit {sha[:12]} was not found in {ref.slug}.")
        else:
            c = _api(f"/repos/{quote(ref.owner)}/{quote(ref.repo)}/commits/{quote(wanted, safe='')}")
            if not c or not _SHA.match(str(c.get("sha", ""))):
                raise GitHubImportError(f"Branch, tag or commit '{wanted}' was not found in {ref.slug}.")
            sha = c["sha"]
        commit_date = ((c.get("commit") or {}).get("committer") or {}).get("date")
        step(f"Downloading archive of commit {sha[:12]}")
        data = request_bytes(f"https://codeload.github.com/{quote(ref.owner)}/{quote(ref.repo)}/zip/{sha}",
                             max_bytes=LIMITS.max_upload_bytes)
        if not data:
            raise GitHubImportError("GitHub did not return an archive for this commit.")
    except RequestBlocked as exc:
        raise GitHubImportError("Download blocked by the egress policy.") from exc
    except ProviderError as exc:
        if "size limit" in str(exc):
            raise GitHubImportError(f"Repository archive exceeds the {LIMITS.max_upload_bytes // (1024 * 1024)} MB limit. "
                                    "Upload a ZIP of the relevant folder instead.") from exc
        raise GitHubImportError("Could not download the repository archive from GitHub.") from exc
    step("Checking archive safety")
    try:
        src = ZipSource(data, f"{ref.slug}@{sha[:12]}")
    except UnsafeInputError as exc:
        raise GitHubImportError(str(exc)) from exc
    src.name = ref.slug
    provenance = {
        "type": "github", "repository": ref.slug, "url": f"https://github.com/{ref.slug}",
        "requested_ref": ref.ref, "resolved_ref": wanted, "commit": sha,
        "commit_url": f"https://github.com/{ref.slug}/commit/{sha}", "commit_date": commit_date,
        "default_branch": meta.get("default_branch"), "archive_bytes": len(data),
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "description": str(meta.get("description") or "")[:300],
    }
    src.origin = provenance
    return src, provenance
