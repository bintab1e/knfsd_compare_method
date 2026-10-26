---
name: knfsd-vuln-pipeline
description: Run or inspect the evidence-driven NFS 1-day comparative-analysis pipeline that maps transferable vulnerability patterns to Linux KNFSD v7.3, generates CodeQL rule plans, validates candidates with the KNFSD syzkaller environment, and evolves rules by round. Use for this repository's ingestion, extraction, mapping, pattern, CodeQL, validation, adjudication, or round-management work. Do not use for unrelated kernel analysis.
---

# KNFSD vulnerability pipeline

Work from the repository root. Read `AGENTS.md` and the relevant contract before taking action.

## Operating invariants

- Treat `data/raw/` as immutable evidence.
- Keep normalized facts separate from LLM extraction, KNFSD mapping, Pattern IR, candidate evidence, and round results.
- Permit Pattern IR and CodeQL generation only for mappings classified `direct`, `semantic`, or `conditional` against KNFSD `v7.3` remote NFS/RPC paths.
- Limit active target mappings and rules to NFSv3, v4.0, v4.1, and v4.2; preserve NFSv2 source evidence but exclude it from this campaign.
- Preserve every raw log and attach evidence identifiers to every material LLM claim.
- Never treat missing KASAN/KCSAN output as a false positive.
- Keep Development, Validation, and Sealed Holdout access boundaries from `config/dataset-split.yaml`.
- Run every LLM role through `compare-codex-job`; do not change `gpt-5.6-sol` or `xhigh` without an explicit repository decision.

## Routes

- For spreadsheet ingestion, evidence acquisition, campaign initialization, or data-quality review, read [pipeline stages](references/pipeline.md), then use `compare-ingest`, `compare-fetch-evidence`, `compare-pipeline`, or `compare-validate`.
- For LLM extraction, review, KNFSD mapping, clustering, adjudication, or refinement, read [evidence and verdict policy](references/evidence-policy.md) and use the matching prompt and JSON Schema.
- Before accepting a KNFSd mapping, generate a hashed exact-v7.3 context pack with `compare-context-pack` and run the independent `mapping-reviewer`. Do not promote the mapper's proposal directly.
- Generate a structured rule plan with `rule-planner` only from independently reviewed Pattern IR and exact-v7.3 source context. Compile and test each CodeQL query before scanning; a plan is not an executable rule.
- Generate executable queries through `codeql-author`, independently check them with `codeql-reviewer`, and materialize them with `compare-codeql-artifact`. Require compile plus positive and safe-negative qltests before a full-database scan.
- For CodeQL or runtime-validation work, read both references. Do not claim completion when CodeQL, kernel, or QEMU artifacts are unavailable; create a reproducible blocked artifact or explicit capability gap instead.

## Campaign operation

1. Initialize or inspect the campaign with `compare-pipeline`. Use bounded `--max-jobs` batches and rerun the same stage to resume.
2. Do not use `--allow-fact-only` for authoritative extraction. Fetch and hash patch/reference evidence first.
3. Treat mapper output as a proposal. Build an exact-v7.3 context pack and require `mapping-reviewer` acceptance before grouping.
4. Run each accepted pattern through `compare-round-pipeline`; its round number is independent of every other pattern.
5. Dispatch exact RPC jobs through the built-in adapter and other paths through the pinned syzkaller Stage 1 boundary. Missing adapter capability is `harness_gap`.
6. Close the round only after every candidate has both runtime records and an independent verdict. Refine from Development evidence only.
7. Use `compare-promotion` for the final gate. Validation and milestone Holdout outcomes are evaluation inputs, never generator/refiner inputs.

## Completion

Run `scripts/check.sh`, validate changed JSON against `schemas/`, retain manifests and hashes, and report exact incomplete stages. Never silently promote a proposal file to an authoritative artifact. A configured pipeline is not the same as a completed 676-case campaign; use campaign and round status as the authority.
