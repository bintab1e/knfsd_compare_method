from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from .common import repo_root


def validate(repo: Path) -> list[str]:
    messages: list[str] = []
    schemas: dict[str, dict] = {}
    for path in sorted((repo / "schemas").glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
    messages.append(f"schemas: {len(schemas)} valid")

    for path in sorted((repo / "config").glob("*.yaml")) + sorted((repo / "registry").glob("*.yaml")):
        yaml.safe_load(path.read_text(encoding="utf-8"))
    messages.append("yaml: valid")

    llm = yaml.safe_load((repo / "config" / "llm.yaml").read_text(encoding="utf-8"))
    if llm.get("model") != "gpt-5.6-sol" or llm.get("reasoning_effort") != "xhigh":
        raise ValueError("LLM must be pinned to gpt-5.6-sol with xhigh reasoning")
    if not llm.get("ephemeral") or not llm.get("ignore_user_config"):
        raise ValueError("LLM roles must use fresh ephemeral sessions and ignore user config")
    if llm.get("cyber_access_program") != "daybreak_blue":
        raise ValueError("Authorized defensive security jobs must request Daybreak Blue")
    if llm.get("timeout_seconds") != 3600:
        raise ValueError("LLM roles must have the pinned 3600 second timeout")
    messages.append("llm pin: gpt-5.6-sol/xhigh with Daybreak Blue and 3600s timeout")

    source_config = yaml.safe_load((repo / "config" / "sources.yaml").read_text(encoding="utf-8"))
    if len(source_config.get("sources", [])) != 8:
        raise ValueError("Exactly eight source implementations are required")
    messages.append("sources: 8 configured")

    runtime = yaml.safe_load((repo / "config" / "runtime-harness.yaml").read_text(encoding="utf-8"))
    if runtime["kernel"]["required_ref"] != "v7.3":
        raise ValueError("Runtime harness must override the kernel ref to exact v7.3")
    target = yaml.safe_load((repo / "config" / "target-knfsd-v7.3.yaml").read_text(encoding="utf-8"))
    protocols = target.get("protocol_scope", {})
    if protocols.get("included") != ["nfs3", "nfs4.0", "nfs4.1", "nfs4.2"]:
        raise ValueError("Active target protocols must be NFSv3, v4.0, v4.1, and v4.2")
    if protocols.get("excluded") != ["nfs2"]:
        raise ValueError("NFSv2 must be explicitly excluded")
    if set(runtime.get("profiles", {})) != {"kasan", "kcsan"}:
        raise ValueError("Runtime harness must define separate KASAN and KCSAN profiles")
    if runtime["profiles"]["kcsan"].get("effective_target_reached_run_limit") != 100:
        raise ValueError("KCSAN effective target-reached run limit must be 100")
    messages.append("runtime harness: pinned with KASAN/KCSAN profiles")

    codeql = yaml.safe_load((repo / "config" / "codeql.yaml").read_text(encoding="utf-8"))
    if codeql.get("version") != "2.27.3":
        raise ValueError("CodeQL CLI must be pinned to 2.27.3")
    if codeql.get("language") != "cpp":
        raise ValueError("Kernel CodeQL language must be cpp")
    if codeql.get("scan", {}).get("ram_mb") != 4096:
        raise ValueError("CodeQL scan RAM must be pinned to 4096 MiB")
    if codeql.get("scan", {}).get("timeout_seconds") != 900:
        raise ValueError("CodeQL scan timeout must be pinned to 900 seconds")
    if codeql.get("database", {}).get("path") != "codeql-db/linux-v7.3-vanilla-v4":
        raise ValueError("CodeQL database path must identify the verified v7.3 target database")
    if codeql.get("database", {}).get("expected_source_commit") != (
        "c03c1a14507dfaf8b856c2608f9ac216021fc222"
    ):
        raise ValueError("CodeQL database source must be pinned to exact vanilla Linux v7.3")
    messages.append("CodeQL: 2.27.3/cpp pinned")

    query_pack = repo / "codeql" / "knfsd-rules"
    required_queries = {
        "DecodedCountSources.ql",
        "CountedDataStorageSinks.ql",
        "DirectDecodedCountToStorage.ql",
        "MissingCountedDataGuardPair.ql",
        "MissingCountedDataGuardPairV2.ql",
    }
    missing_queries = sorted(name for name in required_queries if not (query_pack / name).is_file())
    if not (query_pack / "qlpack.yml").is_file() or missing_queries:
        raise ValueError(f"Missing KNFSd CodeQL pack or queries: {missing_queries}")
    pack_config = yaml.safe_load((query_pack / "qlpack.yml").read_text(encoding="utf-8"))
    if pack_config.get("extractor") != "cpp":
        raise ValueError("KNFSd CodeQL pack must declare the cpp extractor for qltest")
    required_test_files = {
        "CountedDataGuardPair.qll": query_pack / "CountedDataGuardPair.qll",
        "positive/negative control source": query_pack / "tests" / "MissingCountedDataGuardPairV2" / "control.c",
        "guard-pair qltest": query_pack / "tests" / "MissingCountedDataGuardPairV2" / "Test.ql",
        "guard-pair expected output": query_pack / "tests" / "MissingCountedDataGuardPairV2" / "Test.expected",
    }
    missing_tests = [name for name, path in required_test_files.items() if not path.is_file()]
    if missing_tests:
        raise ValueError(f"Missing CodeQL library/test artifacts: {missing_tests}")
    messages.append(f"CodeQL queries: {len(required_queries)} present")

    case_schema = schemas["case.schema.json"]
    case_validator = Draft202012Validator(case_schema)
    case_paths = sorted((repo / "data" / "cases").glob("*.json"))
    for path in case_paths:
        case_validator.validate(json.loads(path.read_text(encoding="utf-8")))
    messages.append(f"canonical cases: {len(case_paths)} valid")

    required_prompts = {
        "extractor",
        "extraction-reviewer",
        "mapper",
        "mapping-reviewer",
        "pattern-clusterer",
        "pattern-reviewer",
        "rule-planner",
        "reachability-planner",
        "adjudicator",
        "refiner",
        "codeql-author",
        "codeql-reviewer",
    }
    missing_prompts = sorted(
        name for name in required_prompts if not (repo / "prompts" / f"{name}.md").is_file()
    )
    if missing_prompts:
        raise ValueError(f"Missing prompts: {missing_prompts}")
    messages.append(f"prompts: {len(required_prompts)} present")

    split = yaml.safe_load((repo / "config" / "dataset-split.yaml").read_text(encoding="utf-8"))
    if split.get("unit") != "root_cause_group":
        raise ValueError("Dataset split unit must be root_cause_group")
    if abs(sum(float(split[name]) for name in ("development", "validation", "sealed_holdout")) - 1.0) > 1e-9:
        raise ValueError("Dataset split ratios must sum to 1.0")
    if split.get("sealed_holdout_feedback_allowed") is not False:
        raise ValueError("Sealed Holdout feedback must remain disabled")
    messages.append("dataset split: 70/15/15 root-cause-group policy")

    adapters = yaml.safe_load((repo / "config" / "validation-adapters.yaml").read_text(encoding="utf-8"))
    if adapters.get("terminal_on_missing_capability") != "harness_gap":
        raise ValueError("Missing validation capability must terminate as harness_gap")
    if set(adapters.get("rpc_templates", {})) != {
        "nfsd4_decode_setclientid",
        "nfsd4_decode_verify",
        "svcauth_gss_legacy_init",
    }:
        raise ValueError("Configured RPC template registry drifted")
    messages.append("validation adapters: exact RPC plus syzkaller Stage 1")

    evidence = yaml.safe_load((repo / "config" / "evidence-sources.yaml").read_text(encoding="utf-8"))
    if evidence.get("allowed_schemes") != ["https"]:
        raise ValueError("Evidence collector must remain HTTPS-only")
    if not evidence.get("allowed_hosts") or int(evidence.get("max_bytes_per_reference", 0)) > 5_242_880:
        raise ValueError("Evidence collector host allowlist or byte limit is invalid")
    messages.append("evidence fetch: HTTPS allowlist and 5 MiB bound")
    return messages


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=repo_root())
    args = parser.parse_args()
    for message in validate(args.repo.resolve()):
        print(f"OK: {message}")


if __name__ == "__main__":
    main()
