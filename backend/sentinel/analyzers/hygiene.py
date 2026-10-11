"""Repository hygiene: accidental secret exposure and CI/CD workflow risks.

This is a lightweight, clearly-labelled check — not a replacement for a dedicated secret
scanner. Detected values are REDACTED before they leave this module; raw secrets are never
stored, logged, returned by the API, or sent anywhere.
"""
from __future__ import annotations

import math
import re
from collections import Counter

import yaml

from ..config import LIMITS
from ..reposource import RepoSource
from .heuristics import signal

SECRET_RULES = [
    ("aws_access_key", "AWS access key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high"),
    ("github_token", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), "high"),
    ("github_pat", "GitHub fine-grained token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), "high"),
    ("slack_token", "Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,200})\b"), "high"),
    ("stripe_key", "Stripe secret key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,99})\b"), "high"),
    ("google_api_key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "medium"),
    ("npm_token", "npm access token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "high"),
    ("private_key", "Private key material", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), "critical"),
    ("jwt", "JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium"),
    ("url_credentials", "Credentials embedded in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://([^\s:/@'\"]{1,64}:[^\s@/'\"]{3,128})@[\w.-]+"), "high"),
    ("generic_secret", "Hard-coded secret assignment",
     re.compile(r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']([^"'\s$]{8,128})["']"""), "medium"),
]
TEXT_EXT = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php",
            ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".xml", ".sh", ".txt",
            ".md", ".tf", ".npmrc", ".pypirc", ".netrc", "Dockerfile")
PLACEHOLDERS = re.compile(r"(?i)(example|changeme|change_me|your[_-]?|xxx+|dummy|placeholder|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|redacted|\*\*\*)")
KNOWN_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE"}


def redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:4]}{'*' * min(12, len(value) - 6)}{value[-2:]} ({len(value)} chars)"


def _entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0.0


def scan_secrets(src: RepoSource) -> list[dict]:
    findings = []
    count = 0
    for path in src.list_files():
        base = path.rsplit("/", 1)[-1]
        if "/node_modules/" in f"/{path}" or path.startswith(("node_modules/", ".git/")):
            continue
        if base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "go.sum"):
            continue
        if not (path.endswith(TEXT_EXT) or base.startswith(".env") or base in (".npmrc", ".pypirc", ".netrc", "Dockerfile")):
            continue
        count += 1
        if count > LIMITS.max_secret_scan_files:
            break
        text = src.read_text(path, 1024 * 1024)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines()[:50000], 1):
            if len(line) > 4000:
                continue
            for rule, label, rx, sev in SECRET_RULES:
                for m in rx.finditer(line):
                    val = m.group(1)
                    is_example = val in KNOWN_EXAMPLES or bool(PLACEHOLDERS.search(val))
                    if rule == "generic_secret" and (is_example or _entropy(val) < 3.0):
                        continue
                    conf = "low" if is_example else ("high" if rule not in ("generic_secret", "jwt") else "medium")
                    f = signal("secret_" + rule, f"{label} in {base}", "low" if is_example else sev, conf,
                               f"{path}:{lineno} contains what looks like a {label.lower()}: {redact(val)}"
                               + (" (matches a documented example/placeholder value)" if is_example else ""),
                               "Pattern-based secret detection (local only, value redacted)",
                               "Secrets committed to a repository should be considered compromised: revoke/rotate them and "
                               "load them from a secret manager or CI secret store. This check is a basic safety net, not a "
                               "replacement for a dedicated secret scanner.", "Secret exposure", finding_kind="secret")
                    f["file"], f["line"] = path, lineno
                    f["evidence"][0]["file"], f["evidence"][0]["line"] = path, lineno
                    findings.append(f)
            if len(findings) > 200:
                return findings
    return findings


# --------------------------------------------------------------------------- CI/CD workflows

_UNTRUSTED_CTX = re.compile(r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|"
                            r"comment\.body|review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.message|"
                            r"head_commit\.message|head_commit\.author\.(?:email|name)|pull_request\.head\.ref|"
                            r"pull_request\.head\.label|workflow_run\.head_branch)[^}]*\}\}")


def scan_workflows(src: RepoSource) -> list[dict]:
    out = []
    for path in src.list_files():
        if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
            continue
        text = src.read_text(path, 512 * 1024) or ""
        try:
            wf = yaml.safe_load(text)
        except yaml.YAMLError:
            out.append(_ci(path, "ci_parse_error", "Workflow could not be parsed", "info", "high",
                           f"{path} is not valid YAML.", "Fix the syntax so it can be reviewed."))
            continue
        if not isinstance(wf, dict):
            continue
        triggers = wf.get("on", wf.get(True))  # PyYAML parses bare `on:` as True
        trig_names = set(triggers.keys()) if isinstance(triggers, dict) else ({triggers} if isinstance(triggers, str) else set(triggers or []))
        perms = wf.get("permissions")
        if perms is None:
            out.append(_ci(path, "ci_default_permissions", "No top-level permissions block", "low", "medium",
                           f"{path} does not set `permissions:`; the GITHUB_TOKEN gets the repository default, which may be read/write.",
                           "Declare least-privilege permissions (e.g. `permissions: contents: read`)."))
        elif perms == "write-all" or (isinstance(perms, dict) and any(v == "write" for v in perms.values()) and len(perms) > 3):
            out.append(_ci(path, "ci_excessive_permissions", "Workflow grants broad write permissions", "medium", "high",
                           f"{path} sets permissions: {perms if isinstance(perms, str) else 'write on ' + ', '.join(k for k, v in perms.items() if v == 'write')}.",
                           "Grant write scopes only to the jobs that need them."))
        jobs = wf.get("jobs") or {}
        prt = bool(trig_names & {"pull_request_target", "workflow_run"})
        for jname, job in (jobs.items() if isinstance(jobs, dict) else []):
            if not isinstance(job, dict):
                continue
            for i, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str) and "@" in uses and not uses.startswith(("./", "docker://")):
                    ref = uses.split("@", 1)[1]
                    if not re.fullmatch(r"[0-9a-f]{40}", ref):
                        owner = uses.split("/", 1)[0]
                        sev = "low" if owner in ("actions", "github") else "medium"
                        out.append(_ci(path, "ci_unpinned_action", f"Action not pinned to a commit: {uses}", sev, "high",
                                       f"{path} job '{jname}' uses {uses} (mutable tag/branch '{ref}').",
                                       "Tags can be moved to malicious commits (e.g. the 2025 tj-actions/changed-files compromise). "
                                       "Pin third-party actions to a full commit SHA."))
                if prt and isinstance(uses, str) and uses.startswith("actions/checkout"):
                    w = step.get("with") or {}
                    ref = str(w.get("ref", ""))
                    if "head" in ref or "pull_request" in ref:
                        out.append(_ci(path, "ci_pwn_request", "pull_request_target checks out untrusted PR code", "critical", "high",
                                       f"{path} job '{jname}' runs on {', '.join(sorted(trig_names & {'pull_request_target', 'workflow_run'}))} "
                                       f"and checks out ref '{ref}'.",
                                       "This runs attacker-controlled code with access to secrets and a write token ('pwn request'). "
                                       "Use `pull_request` for untrusted code, or never execute the checked-out code."))
                run = step.get("run")
                if isinstance(run, str):
                    for m in _UNTRUSTED_CTX.finditer(run):
                        out.append(_ci(path, "ci_script_injection", "Untrusted event data interpolated into a shell script",
                                       "high", "high",
                                       f"{path} job '{jname}' step {i + 1} interpolates {m.group(0)[:80]} directly into `run:`.",
                                       "An attacker can craft a title/branch name containing shell commands. Pass the value "
                                       "through an environment variable and quote it."))
                    if re.search(r"\$\{\{\s*secrets\.[A-Za-z_]+\s*\}\}", run) and re.search(r"\b(echo|printf|cat)\b", run):
                        out.append(_ci(path, "ci_secret_echo", "Secret may be printed in a run step", "medium", "medium",
                                       f"{path} job '{jname}' step {i + 1} references a secret in a command that prints output.",
                                       "Avoid echoing secrets; GitHub masking is best-effort and fails for transformed values."))
                    if re.search(r"curl[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh", run):
                        out.append(_ci(path, "ci_curl_pipe_shell", "Remote script piped to shell", "medium", "high",
                                       f"{path} job '{jname}' step {i + 1} pipes a downloaded script into a shell.",
                                       "Download, verify a checksum/signature, then execute."))
    return out


def _ci(path, kind, title, sev, conf, obs, expl) -> dict:
    f = signal(kind, title, sev, conf, obs, "GitHub Actions workflow analysis (static)", expl, "CI/CD", finding_kind="ci")
    f["file"] = path
    return f
