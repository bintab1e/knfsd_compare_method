from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .common import repo_root, sha256_file, write_json

KERNEL_REF_RE = re.compile(
    r"^(?P<commit>[0-9a-f]{40}):(?P<path>[^:]+):(?P<ranges>[0-9,-]+)$"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
INDIRECT_BINDING_TOKENS = (
    "xpo_recvfrom",
    "vs_dispatch",
    "pc_decode",
    "pc_func",
    "op_func",
    "process.dispatch",
    "aops->accept",
    "pg_vers",
    "vs_proc",
)
BRIDGE_SYMBOLS = (
    "svc_handle_xprt",
    "nfsd_init_request",
    "svc_generic_init_request",
    "svc_get_auth_ops",
    "svc_auth_register",
    "gss_svc_init",
)
REFERENCE_IDENTIFIERS = (
    "svcauthops_gss",
    "nfsd_programs",
    "nfsd_version3",
    "nfsd_version4",
    "NFSD_SUPPORTED_MINOR_VERSION",
)
BRIDGE_FILES = (
    "include/linux/sunrpc/xdr.h",
    "fs/nfsd/nfsd.h",
    "net/sunrpc/svc_xprt.c",
    "net/sunrpc/svc.c",
    "net/sunrpc/svcauth.c",
    "net/sunrpc/auth_gss/svcauth_gss.c",
    "fs/nfsd/nfssvc.c",
)


def _git(source: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def _parse_ranges(spec: str) -> list[tuple[int, int]]:
    result = []
    for part in spec.split(","):
        if "-" in part:
            start_text, end_text = part.split("-", 1)
        else:
            start_text = end_text = part
        start, end = int(start_text), int(end_text)
        if start < 1 or end < start:
            raise ValueError(f"Invalid source range: {part}")
        result.append((start, end))
    return result


def _safe_file(source: Path, relative: str) -> Path:
    candidate = (source / relative).resolve()
    source_resolved = source.resolve()
    if candidate != source_resolved and source_resolved not in candidate.parents:
        raise ValueError(f"Source path escapes kernel tree: {relative}")
    return candidate


def _numbered_text(lines: list[str], start: int, end: int) -> str:
    return "\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1))


def _definition_span(lines: list[str], name: str, name_line: int) -> tuple[int, int] | None:
    """Return a function body span, rejecting ordinary calls and declarations."""
    start_index = name_line - 1
    signature_text = "\n".join(lines[start_index : min(len(lines), start_index + 50)])
    match = re.search(rf"\b{re.escape(name)}\s*\(", signature_text)
    if match is None:
        return None

    open_index = signature_text.find("(", match.start())
    depth = 0
    close_index = None
    for index in range(open_index, len(signature_text)):
        char = signature_text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                close_index = index
                break
    if close_index is None:
        return None

    suffix = signature_text[close_index + 1 :]
    brace_offset = suffix.find("{")
    semicolon_offset = suffix.find(";")
    if brace_offset < 0 or (semicolon_offset >= 0 and semicolon_offset < brace_offset):
        return None

    brace_index = close_index + 1 + brace_offset
    brace_line_index = start_index + signature_text[:brace_index].count("\n")
    depth = 0
    opened = False
    for index in range(brace_line_index, min(len(lines), brace_line_index + 500)):
        line = lines[index]
        if index == brace_line_index:
            column = brace_index - signature_text.rfind("\n", 0, brace_index) - 1
            line = line[column:]
        depth += line.count("{") - line.count("}")
        opened = opened or "{" in line
        if opened and depth == 0:
            return name_line, index + 1
    return None


def _symbol_definitions(source: Path, files: list[str], name: str, max_body_lines: int) -> list[dict[str, Any]]:
    if not IDENTIFIER_RE.fullmatch(name):
        return []
    signature = re.compile(rf"\b{re.escape(name)}\s*\(")
    results = []
    for relative in files:
        path = _safe_file(source, relative)
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_number, line in enumerate(lines, 1):
            match = signature.search(line)
            if match is None:
                continue
            prefix = line[: match.start()]
            if re.search(r"\b(?:if|while|for|switch|return|sizeof)\b", prefix):
                continue
            if any(operator in prefix for operator in ("=", "!", "->", ".", ",")):
                continue
            span = _definition_span(lines, name, line_number)
            if span is None:
                continue
            start, end = span
            captured_end = min(end, start + max_body_lines - 1)
            results.append(
                {
                    "file": relative,
                    "file_sha256": sha256_file(path),
                    "start_line": start,
                    "end_line": end,
                    "captured_end_line": captured_end,
                    "truncated": captured_end < end,
                    "text": _numbered_text(lines, start, captured_end),
                }
            )
            if len(results) >= 4:
                return results
    return results


def _symbol_reference_sites(
    source: Path,
    files: list[str],
    name: str,
    definitions: list[dict[str, Any]],
    max_sites: int = 8,
) -> list[dict[str, Any]]:
    if not IDENTIFIER_RE.fullmatch(name):
        return []
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    definition_spans: dict[str, list[tuple[int, int]]] = {}
    for item in definitions:
        definition_spans.setdefault(item["file"], []).append(
            (item["start_line"], item["end_line"])
        )
    results = []
    for relative in files:
        path = _safe_file(source, relative)
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_number, line in enumerate(lines, 1):
            if not pattern.search(line):
                continue
            if any(start <= line_number <= end for start, end in definition_spans.get(relative, [])):
                continue
            start = max(1, line_number - 4)
            end = min(len(lines), line_number + 4)
            results.append(
                {
                    "file": relative,
                    "file_sha256": sha256_file(path),
                    "match_line": line_number,
                    "captured_start": start,
                    "captured_end": end,
                    "text": _numbered_text(lines, start, end),
                }
            )
            if len(results) >= max_sites:
                return results
    return results


def _token_sites(
    source: Path, files: list[str], token: str, max_sites: int = 12
) -> list[dict[str, Any]]:
    results = []
    for relative in files:
        path = _safe_file(source, relative)
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_number, line in enumerate(lines, 1):
            if token not in line:
                continue
            start = max(1, line_number - 4)
            end = min(len(lines), line_number + 4)
            results.append(
                {
                    "file": relative,
                    "file_sha256": sha256_file(path),
                    "match_line": line_number,
                    "captured_start": start,
                    "captured_end": end,
                    "text": _numbered_text(lines, start, end),
                }
            )
            if len(results) >= max_sites:
                return results
    return results


def build_context_pack(
    mapping_path: Path,
    kernel_source: Path,
    expected_commit: str,
    per_range_limit: int = 240,
    total_line_limit: int = 3000,
) -> dict[str, Any]:
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    head = _git(kernel_source, "rev-parse", "HEAD")
    if head != expected_commit:
        raise ValueError(f"Kernel source HEAD {head} does not match expected {expected_commit}")
    if _git(kernel_source, "status", "--porcelain"):
        raise ValueError("Kernel source tree must be clean")

    entries = []
    missing = []
    captured_lines = 0
    for evidence_ref in mapping.get("evidence_refs", []):
        match = KERNEL_REF_RE.fullmatch(evidence_ref)
        if not match or match.group("commit") != expected_commit:
            continue
        relative = match.group("path")
        path = _safe_file(kernel_source, relative)
        if not path.is_file():
            missing.append({"evidence_ref": evidence_ref, "reason": "file_missing"})
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        snippets = []
        for requested_start, requested_end in _parse_ranges(match.group("ranges")):
            if requested_start > len(lines):
                missing.append({"evidence_ref": evidence_ref, "reason": f"start_line_{requested_start}_past_eof_{len(lines)}"})
                continue
            allowed = min(per_range_limit, total_line_limit - captured_lines)
            if allowed <= 0:
                missing.append({"evidence_ref": evidence_ref, "reason": "context_line_budget_exhausted"})
                continue
            actual_end = min(requested_end, len(lines), requested_start + allowed - 1)
            captured_lines += actual_end - requested_start + 1
            snippets.append(
                {
                    "requested_start": requested_start,
                    "requested_end": requested_end,
                    "captured_start": requested_start,
                    "captured_end": actual_end,
                    "truncated": actual_end < requested_end,
                    "text": _numbered_text(lines, requested_start, actual_end),
                }
            )
        entries.append(
            {
                "evidence_ref": evidence_ref,
                "file": relative,
                "file_sha256": sha256_file(path),
                "line_count": len(lines),
                "snippets": snippets,
            }
        )

    mapped_files = [
        relative
        for relative in mapping.get("target_code", {}).get("files", [])
        if _safe_file(kernel_source, relative).is_file()
    ]
    scan_files = []
    for relative in mapped_files + [entry["file"] for entry in entries] + list(BRIDGE_FILES):
        if relative not in scan_files and _safe_file(kernel_source, relative).is_file():
            scan_files.append(relative)
    symbol_names = []
    proposed_symbols = (
        mapping.get("target_code", {}).get("functions", [])
        + mapping.get("target_code", {}).get("remote_entrypoints", [])
        + list(BRIDGE_SYMBOLS)
        + list(REFERENCE_IDENTIFIERS)
    )
    for name in proposed_symbols:
        if name not in symbol_names:
            symbol_names.append(name)
    symbols = {
        name: _symbol_definitions(kernel_source, scan_files, name, max_body_lines=220)
        for name in symbol_names
    }
    symbol_reference_sites = {
        name: _symbol_reference_sites(kernel_source, scan_files, name, symbols[name])
        for name in symbol_names
    }
    indirect_binding_sites = {
        token: _token_sites(kernel_source, scan_files, token)
        for token in INDIRECT_BINDING_TOKENS
    }

    call_paths = []
    for path in mapping.get("target_code", {}).get("call_paths", []):
        edges = []
        for caller, callee in zip(path, path[1:]):
            caller_defs = symbols.get(caller, [])
            callee_defs = symbols.get(callee, [])
            mentioned = any(re.search(rf"\b{re.escape(callee)}\s*\(", item["text"]) for item in caller_defs) if IDENTIFIER_RE.fullmatch(callee) else False
            if mentioned:
                status = "direct_textual_call"
            elif caller_defs and callee_defs:
                status = "symbol_only"
            else:
                status = "unresolved"
            edges.append(
                {
                    "caller": caller,
                    "callee": callee,
                    "status": status,
                    "caller_definition_found": bool(caller_defs),
                    "callee_definition_found": bool(callee_defs),
                }
            )
        call_paths.append({"proposed_path": path, "edges": edges})

    return {
        "schema_version": "1.0.0",
        "target": "linux-knfsd-v7.3",
        "kernel_ref": "v7.3",
        "kernel_commit": head,
        "kernel_tree_clean": True,
        "mapping_path": str(mapping_path),
        "mapping_sha256": sha256_file(mapping_path),
        "source_root": str(kernel_source),
        "limits": {
            "per_range_lines": per_range_limit,
            "total_lines": total_line_limit,
            "captured_lines": captured_lines,
        },
        "source_entries": entries,
        "missing_evidence": missing,
        "symbols": symbols,
        "symbol_reference_sites": symbol_reference_sites,
        "indirect_binding_sites": indirect_binding_sites,
        "call_path_checks": call_paths,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a hashed KNFSd v7.3 source context pack.")
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--kernel-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", default="c03c1a14507dfaf8b856c2608f9ac216021fc222")
    parser.add_argument("--repo", type=Path, default=repo_root())
    args = parser.parse_args()
    result = build_context_pack(
        args.mapping.resolve(), args.kernel_source.resolve(), args.expected_commit
    )
    write_json(args.output.resolve(), result)
    print(json.dumps({
        "output": str(args.output.resolve()),
        "kernel_commit": result["kernel_commit"],
        "source_entries": len(result["source_entries"]),
        "missing_evidence": len(result["missing_evidence"]),
        "symbols": len(result["symbols"]),
        "captured_lines": result["limits"]["captured_lines"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
