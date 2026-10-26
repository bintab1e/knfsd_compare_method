# KNFSD comparative vulnerability pipeline

This repository turns 1-day records from eight NFS implementations into evidence-backed vulnerability patterns, maps applicable patterns to Linux KNFSD `v7.3`, generates CodeQL rule plans, and tracks static-analysis and runtime-validation rounds.

The repository is intentionally evidence-first:

- Source spreadsheets and normalized facts never contain LLM conclusions.
- LLM extraction, KNFSD mapping, Pattern IR, verdicts, and round results are versioned separately.
- Only cases with a supported remote KNFSD mapping enter Pattern IR and CodeQL generation.
- Missing KASAN/KCSAN output is not a false positive.
- Every LLM role runs as a fresh headless `codex exec` job using `gpt-5.6-sol` with `xhigh` reasoning and JSON Schema output.

## Bootstrap

```bash
cd ~/workspace/tobabz/compare_method
./scripts/bootstrap.sh
```

Run the complete local contract suite at any time:

```bash
./scripts/check.sh
```

## Ingest the spreadsheets

Place the eight source workbooks in `data/raw/`, then run:

```bash
.venv/bin/compare-ingest --repo "$PWD"
```

The command creates one JSON file per normalized case, `data/generated/cases.jsonl`, a manifest, and a data-quality report. It never modifies the workbooks.

## Run a headless LLM job

```bash
.venv/bin/compare-codex-job extractor \
  --input data/cases/CASE-KNFSD-CVE-YYYY-NNNN-RC01.json \
  --output analysis/extractions/CASE-KNFSD-CVE-YYYY-NNNN-RC01/v1.json
```

The wrapper pins the model and effort from `config/llm.yaml`, uses an ephemeral read-only Codex session, and records a provenance manifest without copying authentication material.

## Campaign control plane

Initialize the deterministic root-cause-group split and resumable campaign:

```bash
.venv/bin/compare-pipeline --repo . init \
  --campaign-id CAMPAIGN-KNFSD-V73-001
.venv/bin/compare-pipeline --repo . status \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --partition development
```

KNFSD cases are split 70% Development, 15% Validation, and 15% Sealed Holdout. External implementation analogues stay available to Development. The public split manifest lists Development IDs but only count/hash commitments for Validation and Holdout. Generator and refiner roles fail before a model call if their inputs contain either hidden partition.

Fetch bounded public source evidence before extraction. Only HTTPS references on the repository allowlist are accepted; redirects are rechecked, private addresses are refused, and every payload is size-bounded and hashed.

```bash
.venv/bin/compare-fetch-evidence --repo . --case-id CASE-...-RC01
.venv/bin/compare-fetch-evidence --repo . --all --max-cases 20
```

Run a stage in bounded, resumable batches. Fact-only extraction is blocked by default so that missing patches do not silently become low-quality LLM input.

```bash
.venv/bin/compare-pipeline --repo . run \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --stage extraction --partition development --max-jobs 10
```

The available upstream stages are `extraction`, `extraction-review`, `mapping`, `context`, `mapping-review`, `pattern`, `pattern-review`, `rule-plan`, `codeql-author`, `codeql-review`, and `codeql-materialize`. Every LLM call goes through `compare-codex-job`, uses a fresh ephemeral `gpt-5.6-sol`/`xhigh` Daybreak Blue session, validates structured output, and records input/prompt/schema hashes.

## Pattern rounds

Each pattern has an independent round manifest and sequence:

```bash
.venv/bin/compare-round-pipeline --repo . init \
  --campaign-id CAMPAIGN-KNFSD-V73-001 --round 1 \
  --pattern-ir patterns/.../v1.reviewed.json \
  --rule-plan patterns/.../rule-plan-v1.json \
  --codeql-artifact patterns/.../codeql-v1.reviewed.json \
  --context target-map/context/.../v1.json
```

Then run `scan`, `normalize`, `plan-validation`, both `validate-runtime` sanitizer profiles, `adjudicate`, `close`, and `refine`. CodeQL artifacts cannot scan until materialization, compile, positive/negative qltest, and full-database gates pass. Validation dispatch uses an exact RPC adapter where one exists and otherwise hands the source location to the pinned `knfsd-syzkaller` Stage 1 boundary; an unavailable capability becomes `harness_gap`, never FP.

Promotion is a separate deterministic policy decision:

```bash
.venv/bin/compare-promotion --repo . \
  --baseline evaluation/v1.json --candidate evaluation/v2.json \
  --output evaluation/v2.promotion.json
```

A version advances only when it preserves known TP, adds a TP or removes a confirmed FP, does not regress Validation, and avoids candidate/runtime explosion. Sealed Holdout is milestone-only and never becomes refinement feedback.

## Verified implementation boundary

The control plane, contracts, split guard, evidence collector, campaign state, CodeQL author/materializer gate, runtime adapter dispatch, verdict aggregation, refinement boundary, promotion policy, CI, and reusable Codex skill are implemented. The pinned external artifacts remain uncommitted: CodeQL CLI/database, Linux `v7.3`, KASAN/KCSAN kernels, QEMU image, syzkaller parser bundle, and large logs are referenced by hash.

The initial Ganesha CVE-2017-8779 transfer pattern has already traversed extraction, reviewed KNFSD mapping, CodeQL scanning, KASAN, 100 effective KCSAN runs, independent verdicts, refinement, and a second CodeQL round. That execution validates the vertical path; it does not imply that all 676 source cases have completed their LLM and runtime queues.

## Pipeline order

1. Import eight workbooks as immutable source evidence and canonical fact-only cases.
2. Extract and independently review each case's causal model.
3. Map supported remote NFS/RPC semantics to vanilla KNFSd `v7.3`; exclude non-applicable cases from active analysis without deleting them.
4. Build and independently review versioned Pattern IR.
5. Generate and test KNFSd-specific CodeQL rule variants, then scan the full kernel database.
6. Prove candidate remote reachability and validate KASAN/KCSAN jobs in the knfsd-syzkaller-compatible QEMU environment.
7. Adjudicate intended-pattern match, bug reality, and security relevance separately.
8. Close each pattern's round, apply the false-positive circuit breaker, and refine without sealed-holdout feedback.

## Runtime harness

The KASAN and KCSAN environments both come from `Tobabz/knfsd-syzkaller`. The clone itself and its large build products are intentionally not committed; `config/runtime-harness.yaml` pins the repository commit and binds expected artifacts into this pipeline.

```bash
./scripts/sync_runtime_harness.sh
.venv/bin/compare-runtime-status --repo "$PWD"
```

Provisioning must pass `--kernel-ref v7.3` and build both `--variant kasan` and `--variant kcsan`. A run is not accepted merely because images exist: `runtime/knfsd-v7.3/manifest.json` must resolve the kernel to exact `v7.3`, record passing sanitizer verification, and match the pinned harness commit.

The six harness patches have been apply-tested without conflicts against final `v7.3` (`c03c1a14507dfaf8b856c2608f9ac216021fc222`). The tracked overlay updates the harness BASE pin from `v7.3-rc6` to that final tag; KASAN/KCSAN build and boot verification are still required. The campaign covers v3/v4.0/v4.1/v4.2. NFSv2 is excluded from extraction-to-target mapping, CodeQL activation, and runtime validation.

See `docs/harness-integration.md` for the pinned revisions and runtime evidence, and `docs/campaign-runbook.md` for the resumable operating sequence.
