from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .common import repo_root


def _manifest_kernel_ref(manifest: dict[str, Any] | None) -> str | None:
    if not manifest:
        return None
    kernel = manifest.get("kernel")
    if isinstance(kernel, dict):
        value = kernel.get("ref")
        return value if isinstance(value, str) else None
    value = manifest.get("kernel_ref")
    return value if isinstance(value, str) else None


def _git(path: Path, *args: str) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(path), *args], text=True, capture_output=True, check=False
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def status(repo: Path) -> dict[str, Any]:
    config = yaml.safe_load((repo / "config" / "runtime-harness.yaml").read_text(encoding="utf-8"))
    harness = repo / config["repository"]["local_path"]
    head = _git(harness, "rev-parse", "HEAD") if harness.is_dir() else None
    pinned = config["repository"]["pinned_commit"]
    base_path = harness / "bundle" / "patches" / "BASE"
    base_values: dict[str, str] = {}
    if base_path.is_file():
        for line in base_path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                base_values[key.strip()] = value.strip()
    base_matches = (
        base_values.get("kernel_tag") == config["kernel"]["required_ref"]
        and base_values.get("kernel_commit") == config["kernel"]["bundle_known_base_commit"]
    )
    profile_status = {}
    for name, profile in config["profiles"].items():
        profile_status[name] = {
            "config_exists": (repo / profile["kernel_config"]).is_file(),
            "bzimage_exists": (repo / profile["bzimage"]).is_file(),
            "vmlinux_exists": (repo / profile["vmlinux"]).is_file(),
        }

    manifest_path = repo / config["environment"]["manifest"]
    manifest = None
    manifest_error = None
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            manifest_error = str(exc)
    manifest_kernel_ref = _manifest_kernel_ref(manifest)

    return {
        "schema_version": "1.0.0",
        "harness": {
            "path": str(harness),
            "exists": harness.is_dir(),
            "head": head,
            "pinned_commit": pinned,
            "pin_matches": head == pinned,
            "v7_3_base_overlay_matches": base_matches,
        },
        "kernel": {
            "required_ref": config["kernel"]["required_ref"],
            "bundle_known_base_ref": config["kernel"]["bundle_known_base_ref"],
            "manifest_present": manifest is not None,
            "manifest_error": manifest_error,
            "exact_v7_3_verified": bool(
                manifest
                and manifest_kernel_ref == config["kernel"]["required_ref"]
                and manifest.get("status") == "pass"
            ),
        },
        "profiles": profile_status,
        "runtime_ready": bool(
            head == pinned
            and base_matches
            and manifest
            and manifest_kernel_ref == config["kernel"]["required_ref"]
            and manifest.get("status") == "pass"
            and all(
                item["config_exists"] and item["bzimage_exists"] and item["vmlinux_exists"]
                for item in profile_status.values()
            )
        ),
        "capability_gaps": config["capability_gaps"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Report KNFSd runtime-harness readiness.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    args = parser.parse_args()
    result = status(args.repo.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(
        0
        if result["harness"]["pin_matches"]
        and result["harness"]["v7_3_base_overlay_matches"]
        else 2
    )


if __name__ == "__main__":
    main()
