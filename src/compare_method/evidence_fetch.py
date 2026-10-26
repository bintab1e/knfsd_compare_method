from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import mimetypes
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import yaml

from .common import repo_root, sha256_bytes, sha256_file, write_json


FetchResult = tuple[bytes, str, str]


def _request_url(url: str) -> str:
    """Return a fetchable canonical mirror without weakening URL policy.

    The execution host cannot route to git.kernel.org.  Kernel commit links
    have content-addressed equivalents on the official GitHub mirrors, so we
    fetch those while retaining the original URL in the evidence manifest.
    """
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host == "git.kernel.org":
        commit = None
        stable = re.fullmatch(r"/stable/c/([0-9a-fA-F]{7,64})", parsed.path)
        if stable:
            commit = stable.group(1)
            repository = "gregkh/linux"
        else:
            query_commit = urllib.parse.parse_qs(parsed.query).get("id", [])
            if query_commit and re.fullmatch(r"[0-9a-fA-F]{7,64}", query_commit[0]):
                commit = query_commit[0]
                repository = (
                    "torvalds/linux"
                    if "/torvalds/linux.git/" in parsed.path
                    else "gregkh/linux"
                )
        if commit:
            return f"https://github.com/{repository}/commit/{commit}.patch"
    return url


def _validate_url(url: str, allowed_schemes: set[str], allowed_hosts: set[str]) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in allowed_schemes:
        raise ValueError(f"scheme_not_allowed:{parsed.scheme}")
    if parsed.username or parsed.password:
        raise ValueError("credentials_not_allowed")
    if parsed.port not in (None, 443):
        raise ValueError(f"port_not_allowed:{parsed.port}")
    if host not in allowed_hosts:
        raise ValueError(f"host_not_allowed:{host}")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443)}
    except socket.gaierror as exc:
        raise ValueError(f"dns_failed:{host}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(f"non_public_address:{address}")
    return parsed


def fetch_url(
    url: str,
    *,
    allowed_schemes: set[str],
    allowed_hosts: set[str],
    allowed_content_types: set[str],
    max_bytes: int,
    timeout: int,
) -> FetchResult:
    request_url = _request_url(url)
    parsed = _validate_url(request_url, allowed_schemes, allowed_hosts)
    if (
        parsed.hostname == "github.com"
        and re.fullmatch(r"/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,64}", parsed.path)
        and not parsed.query
    ):
        request_url += ".patch"
    patch_request = urllib.parse.urlparse(request_url).path.endswith((".patch", ".diff"))
    request = urllib.request.Request(
        request_url,
        headers={
            "User-Agent": "tobabz-knfsd-evidence-collector/1.0",
            "Accept": (
                "application/vnd.github.patch, text/x-patch, text/plain"
                if patch_request
                else "text/html, application/json;q=0.9, text/plain;q=0.8, application/pdf;q=0.5"
            ),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        final_url = response.geturl()
        _validate_url(final_url, allowed_schemes, allowed_hosts)
        content_type = response.headers.get_content_type().lower()
        if content_type not in allowed_content_types:
            raise ValueError(f"content_type_not_allowed:{content_type}")
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > max_bytes:
            raise ValueError(f"content_length_exceeds_limit:{declared}")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError(f"body_exceeds_limit:{max_bytes}")
        return body, final_url, content_type


def _extension(url: str, content_type: str) -> str:
    suffix = Path(urllib.parse.urlparse(url).path).suffix.lower()
    if suffix in {".patch", ".diff", ".json", ".html", ".htm", ".md", ".pdf"}:
        return suffix
    explicit = {
        "text/plain": ".txt",
        "text/html": ".html",
        "text/markdown": ".md",
        "text/x-diff": ".patch",
        "text/x-patch": ".patch",
        "application/json": ".json",
        "application/ld+json": ".json",
        "application/pdf": ".pdf",
    }
    if content_type in explicit:
        return explicit[content_type]
    return suffix if 1 <= len(suffix) <= 10 else mimetypes.guess_extension(content_type) or ".bin"


def collect_case(
    case_path: Path,
    output_root: Path,
    config: dict[str, Any],
    fetcher: Callable[..., FetchResult] = fetch_url,
) -> dict[str, Any]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case_id = case["case_id"]
    directory = output_root / case_id / "references"
    previous_path = output_root / case_id / "manifest.json"
    previous = json.loads(previous_path.read_text(encoding="utf-8")) if previous_path.is_file() else {"references": []}
    by_url = {item["url"]: item for item in previous.get("references", [])}
    allowed_schemes = set(config["allowed_schemes"])
    allowed_hosts = set(config["allowed_hosts"])
    allowed_types = set(config["allowed_content_types"])
    records = []
    seen = set()
    for reference in case.get("references", []):
        url = reference.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        existing = by_url.get(url)
        if existing and existing.get("status") == "fetched":
            path = output_root / case_id / existing["path"]
            if path.is_file() and sha256_file(path) == existing.get("sha256"):
                records.append(existing)
                continue
        base = {
            "url": url,
            "kind": reference.get("kind"),
            "source_record_id": reference.get("source_record_id"),
            "source_cell": reference.get("source_cell"),
        }
        try:
            body, final_url, content_type = fetcher(
                url,
                allowed_schemes=allowed_schemes,
                allowed_hosts=allowed_hosts,
                allowed_content_types=allowed_types,
                max_bytes=int(config["max_bytes_per_reference"]),
                timeout=int(config["timeout_seconds"]),
            )
            digest = sha256_bytes(body)
            relative = Path("references") / f"{digest[:20]}{_extension(final_url, content_type)}"
            destination = output_root / case_id / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and sha256_file(destination) != digest:
                raise ValueError("existing_evidence_hash_mismatch")
            if not destination.exists():
                destination.write_bytes(body)
            records.append(
                base
                | {
                    "status": "fetched",
                    "final_url": final_url,
                    "content_type": content_type,
                    "bytes": len(body),
                    "sha256": digest,
                    "path": str(relative),
                    "error": None,
                }
            )
        except (ValueError, OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            records.append(
                base
                | {
                    "status": "blocked_or_failed",
                    "final_url": None,
                    "content_type": None,
                    "bytes": 0,
                    "sha256": None,
                    "path": None,
                    "error": f"{type(exc).__name__}:{exc}",
                }
            )
    manifest = {
        "schema_version": "1.0.0",
        "case_id": case_id,
        "case_path": str(case_path),
        "case_sha256": sha256_file(case_path),
        "references": sorted(records, key=lambda item: item["url"]),
        "counts": {
            "fetched": sum(item["status"] == "fetched" for item in records),
            "blocked_or_failed": sum(item["status"] != "fetched" for item in records),
        },
    }
    write_json(previous_path, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch bounded allowlisted public evidence for canonical cases.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--max-cases", type=int)
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of cases to fetch concurrently (default: 8)",
    )
    args = parser.parse_args()
    if bool(args.case_id) == bool(args.all):
        raise SystemExit("select exactly one of --case-id or --all")
    repo = args.repo.resolve()
    config = yaml.safe_load((repo / "config" / "evidence-sources.yaml").read_text(encoding="utf-8"))
    if args.all:
        paths = sorted((repo / "data" / "cases").glob("*.json"))
    else:
        paths = [repo / "data" / "cases" / f"{case_id}.json" for case_id in args.case_id]
    if args.max_cases is not None:
        paths = paths[: args.max_cases]
    if args.workers < 1 or args.workers > 32:
        raise SystemExit("--workers must be between 1 and 32")
    output_root = repo / "evidence" / "cases"
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(
            executor.map(
                lambda path: collect_case(path, output_root, config),
                paths,
            )
        )
    print(
        json.dumps(
            {
                "cases": len(results),
                "references_fetched": sum(item["counts"]["fetched"] for item in results),
                "references_blocked_or_failed": sum(item["counts"]["blocked_or_failed"] for item in results),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
