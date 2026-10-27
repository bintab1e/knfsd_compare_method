#!/usr/bin/env python3
"""Fail closed when a source-only repository contains outputs or likely secrets."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


FORBIDDEN_PREFIXES = (
    "data/raw/",
    "data/cases/",
    "data/generated/",
    "evidence/",
    "analysis/",
    "codeql/generated/",
    "target-map/generated/",
    "target-map/context/",
    "mappings/",
    "patterns/",
    "campaigns/",
    "candidates/",
    "validation/jobs/",
    "validation/runs/",
    "runs/",
    "artifacts/",
    "external/",
    "runtime/",
    "codeql-db/",
    "kernel/",
)

FORBIDDEN_NAMES = {
    ".env",
    "auth.json",
    "credentials.json",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "id_rsa",
}

FORBIDDEN_SUFFIXES = (
    ".audit.json",
    ".sarif",
    ".log",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".qcow2",
    ".img",
)

SECRET_PATTERNS = {
    "private-key": re.compile(b"-----BEGIN " + b"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "openai-style-key": re.compile(rb"sk-[A-Za-z0-9_-]{20,}"),
    "api-key-assignment": re.compile(
        rb"(?:OPENAI_API_KEY|CODEX_API_KEY)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{16,}",
        re.IGNORECASE,
    ),
    "tailscale-key": re.compile(rb"tskey-[A-Za-z0-9_-]{16,}"),
    "aws-access-key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "slack-token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "bearer-token": re.compile(rb"Bearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    "credential-url": re.compile(rb"https?://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
    "server-home-path": re.compile(rb"/home/[A-Za-z0-9._-]+/"),
    "tailscale-address": re.compile(
        rb"\b100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])(?:\.[0-9]{1,3}){2}\b"
    ),
}


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def candidate_paths(repo: Path) -> list[str]:
    raw = _git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted(item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item)


def _forbidden_path(path: str) -> str | None:
    normalized = PurePosixPath(path).as_posix()
    name = PurePosixPath(normalized).name
    if any(normalized.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
        return "generated/private output path"
    if name in FORBIDDEN_NAMES or name.startswith(".env.") or name.startswith("id_rsa."):
        return "credential filename"
    if normalized.endswith(FORBIDDEN_SUFFIXES):
        return "generated output or credential suffix"
    return None


def _is_probably_binary(raw: bytes) -> bool:
    return b"\0" in raw[:8192]


def audit(repo: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for relative in candidate_paths(repo):
        reason = _forbidden_path(relative)
        if reason:
            findings.append((relative, reason))
            continue
        path = repo / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if _is_probably_binary(raw):
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(raw):
                findings.append((relative, f"possible {label}"))

    for line in _git(repo, "remote", "-v").decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and re.search(r"https?://[^\s/:]+:[^\s/@]+@", fields[1]):
            findings.append((f"git-remote:{fields[0]}", "remote URL contains embedded credentials"))
    return findings


def main() -> int:
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    findings = audit(repo)
    if findings:
        print("PRE-PUSH AUDIT FAILED", file=sys.stderr)
        for path, reason in findings:
            print(f"- {path}: {reason}", file=sys.stderr)
        return 1
    print(f"PRE-PUSH AUDIT PASSED: {len(candidate_paths(repo))} tracked/non-ignored source files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
