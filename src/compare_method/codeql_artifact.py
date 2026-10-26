from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .common import repo_root, sha256_file, write_json


ALLOWED_TEST_SUFFIXES = {".ql", ".qlref", ".cpp", ".c", ".h", ".expected"}
PATTERN_RE = re.compile(r"^PATTERN-[A-Z0-9-]+$")


def _safe_relative(value: str, *, tests: bool) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe artifact path: {value}")
    if any(part in {"", "."} for part in path.parts):
        raise ValueError(f"non-canonical artifact path: {value}")
    if tests:
        if path.parts[0] != "tests" or path.suffix not in ALLOWED_TEST_SUFFIXES:
            raise ValueError(f"invalid CodeQL test path: {value}")
    elif path.parts[0] == "tests" or path.suffix != ".ql":
        raise ValueError(f"invalid CodeQL query path: {value}")
    return path


def validate_artifact(repo: Path, artifact: dict[str, Any], allow_proposed: bool = False) -> None:
    schema = json.loads((repo / "schemas" / "codeql-artifact.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(artifact)
    preflight_statuses = {"proposed", "needs_revision"}
    if artifact["status"] != "accepted" and not (
        allow_proposed and artifact["status"] in preflight_statuses
    ):
        raise ValueError(f"CodeQL artifact status is {artifact['status']}, not accepted")
    if not PATTERN_RE.fullmatch(artifact["pattern_id"]):
        raise ValueError("invalid pattern identifier")
    paths = []
    for query in artifact["queries"]:
        paths.append(str(_safe_relative(query["path"], tests=False)))
        if len(query["content"].encode("utf-8")) > 512_000:
            raise ValueError(f"query is too large: {query['path']}")
    for test in artifact["tests"]:
        paths.append(str(_safe_relative(test["path"], tests=True)))
        if len(test["content"].encode("utf-8")) > 512_000:
            raise ValueError(f"test is too large: {test['path']}")
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate artifact path")
    expectations = {control["expectation"] for control in artifact["controls"]}
    if expectations != {"hit", "no_hit"}:
        raise ValueError("controls must contain both hit and no_hit expectations")
    known_paths = set(paths)
    for control in artifact["controls"]:
        missing = sorted(set(control["test_paths"]) - known_paths)
        if missing:
            raise ValueError(f"control {control['control_id']} references missing files: {missing}")


def materialize(
    repo: Path,
    artifact_path: Path,
    output_root: Path,
    allow_proposed: bool = False,
) -> tuple[Path, dict[str, Any]]:
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    validate_artifact(repo, artifact, allow_proposed=allow_proposed)
    destination = output_root / artifact["pattern_id"] / f"v{artifact['artifact_version']}"
    destination.mkdir(parents=True, exist_ok=True)
    qlpack = {
        "name": artifact["pack"]["name"],
        "version": artifact["pack"]["version"],
        "extractor": "cpp",
        "dependencies": artifact["pack"]["dependencies"],
    }
    qlpack_path = destination / "qlpack.yml"
    rendered_pack = yaml.safe_dump(qlpack, sort_keys=False)
    if qlpack_path.exists() and qlpack_path.read_text(encoding="utf-8") != rendered_pack:
        raise ValueError(f"refusing to overwrite different qlpack: {qlpack_path}")
    qlpack_path.write_text(rendered_pack, encoding="utf-8")

    written = [qlpack_path]
    for item, is_test in [
        *((item, False) for item in artifact["queries"]),
        *((item, True) for item in artifact["tests"]),
    ]:
        relative = _safe_relative(item["path"], tests=is_test)
        path = destination.joinpath(*relative.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = item["content"]
        if path.exists() and path.read_text(encoding="utf-8") != content:
            raise ValueError(f"refusing to overwrite different artifact file: {path}")
        path.write_text(content, encoding="utf-8")
        written.append(path)

    manifest = {
        "schema_version": "1.0.0",
        "pattern_id": artifact["pattern_id"],
        "artifact_version": artifact["artifact_version"],
        "source_artifact": str(artifact_path),
        "source_artifact_sha256": sha256_file(artifact_path),
        "files": [
            {"path": str(path.relative_to(destination)), "sha256": sha256_file(path)}
            for path in sorted(written)
        ],
        "gate": {"materialized": True, "compiled": False, "qltests_passed": False, "scanned": False},
    }
    write_json(destination / "manifest.json", manifest)
    return destination, manifest


def _output_tail(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-4000:]


def _run(
    command: list[str], cwd: Path, *, timeout_seconds: int | None = None
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "exit_code": 124,
            "timeout_seconds": timeout_seconds,
            "timed_out": True,
            "stdout_tail": _output_tail(exc.stdout),
            "stderr_tail": _output_tail(exc.stderr),
        }
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout_tail": _output_tail(completed.stdout),
        "stderr_tail": _output_tail(completed.stderr),
    }


def verify_pack(
    repo: Path,
    pack_dir: Path,
    *,
    database: Path | None = None,
    sarif_output: Path | None = None,
) -> dict[str, Any]:
    config = yaml.safe_load((repo / "config" / "codeql.yaml").read_text(encoding="utf-8"))
    executable = repo / config["bundle"]["local_path"]
    if executable.is_dir():
        executable = executable / "codeql"
    if not executable.is_file():
        raise FileNotFoundError(f"pinned CodeQL executable is missing: {executable}")
    query_paths = sorted(path for path in pack_dir.rglob("*.ql") if "tests" not in path.parts)
    if not query_paths:
        raise ValueError(f"no queries in {pack_dir}")
    steps = []
    install = _run([str(executable), "pack", "install"], pack_dir)
    steps.append({"name": "pack_install", **install})
    compile_steps = []
    if install["exit_code"] == 0:
        for query in query_paths:
            result = _run([str(executable), "query", "compile", str(query)], pack_dir)
            compile_steps.append({"query": str(query), **result})
    steps.append({"name": "compile", "queries": compile_steps})
    compiled = bool(compile_steps) and all(item["exit_code"] == 0 for item in compile_steps)

    test_dir = pack_dir / "tests"
    qltests = {"command": [], "exit_code": 2, "stderr_tail": "tests directory missing", "stdout_tail": ""}
    if compiled and test_dir.is_dir():
        qltests = _run([str(executable), "test", "run", str(test_dir)], pack_dir)
    steps.append({"name": "qltest", **qltests})
    qltests_passed = qltests["exit_code"] == 0

    scanned = False
    if database is not None:
        if not compiled or not qltests_passed:
            steps.append({"name": "scan", "exit_code": 2, "reason": "compile_or_qltest_gate_failed"})
        elif sarif_output is None:
            raise ValueError("sarif_output is required with database")
        else:
            sarif_output.parent.mkdir(parents=True, exist_ok=True)
            scan_config = config.get("scan", {})
            ram_mb = int(scan_config.get("ram_mb", 4096))
            timeout_seconds = int(scan_config.get("timeout_seconds", 900))
            if ram_mb <= 0 or timeout_seconds <= 0:
                raise ValueError("CodeQL scan ram_mb and timeout_seconds must be positive")
            scan = _run(
                [
                    str(executable),
                    "database",
                    "analyze",
                    f"--ram={ram_mb}",
                    str(database),
                    *[str(path) for path in query_paths],
                    "--format=sarifv2.1.0",
                    f"--output={sarif_output}",
                    "--rerun",
                ],
                pack_dir,
                timeout_seconds=timeout_seconds,
            )
            scanned = scan["exit_code"] == 0 and sarif_output.is_file()
            steps.append({"name": "scan", **scan})

    result = {
        "schema_version": "1.0.0",
        "pack_dir": str(pack_dir),
        "codeql_version": config["version"],
        "steps": steps,
        "gate": {
            "materialized": True,
            "compiled": compiled,
            "qltests_passed": qltests_passed,
            "scanned": scanned,
        },
    }
    write_json(pack_dir / "verification.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize and gate an LLM-authored CodeQL artifact.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=Path("codeql/generated"))
    parser.add_argument(
        "--allow-proposed",
        action="store_true",
        help="Permit proposed or needs_revision artifacts for deterministic preflight only",
    )
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--sarif-output", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    output_root = args.output_root if args.output_root.is_absolute() else repo / args.output_root
    pack_dir, manifest = materialize(
        repo, args.artifact.resolve(), output_root, allow_proposed=args.allow_proposed
    )
    result: dict[str, Any] = {"pack_dir": str(pack_dir), "manifest": manifest}
    if args.verify:
        database = args.database.resolve() if args.database else None
        sarif = args.sarif_output.resolve() if args.sarif_output else None
        result["verification"] = verify_pack(repo, pack_dir, database=database, sarif_output=sarif)
    print(json.dumps(result, indent=2))
    if args.verify:
        gate = result["verification"]["gate"]
        required = gate["compiled"] and gate["qltests_passed"]
        if database is not None:
            required = required and gate["scanned"]
        if not required:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
