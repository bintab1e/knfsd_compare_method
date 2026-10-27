# KNFSD v7.3 campaign runbook

## Safety and evidence boundaries

- Work only from a campaign manifest and its immutable split hash.
- Never pass Validation or Sealed Holdout cases, labels, or outcomes to `pattern-clusterer`, `pattern-reviewer`, `rule-planner`, `codeql-author`, `codeql-reviewer`, or `refiner`.
- Keep NFSv2 records, but do not activate them in extraction-to-KNFSd mappings, rules, scans, or runtime jobs.
- A missing sanitizer signal is `no_signal`, `no_signal_after_100`, `unreached`, `insufficient_runs`, or `harness_gap`; it is not `confirmed_fp`.
- Do not run LLM batches without a bounded `--max-jobs`. Status and prior outputs make every stage resumable.

## 1. Readiness

```bash
./scripts/check.sh
.venv/bin/compare-runtime-status --repo .
```

`runtime_ready` must be true for live KASAN/KCSAN validation. CodeQL compile/qltest can run without the QEMU environment, but a full scan additionally requires the pinned database from `config/codeql.yaml`.

## 2. Dataset and evidence

```bash
.venv/bin/compare-ingest --repo .
.venv/bin/compare-pipeline --repo . init \
  --campaign-id CAMPAIGN-KNFSD-V73-001
.venv/bin/compare-fetch-evidence --repo . --all --workers 8
```

Review `evidence/cases/*/manifest.json` after each batch. Collection is
content-addressed and resumable: already verified payloads are reused. Blocked
URLs stay explicit. Do not weaken the host allowlist to make a batch green.

## 3. Development roles and fast feedback

Run and inspect each stage before advancing:

```bash
for stage in extraction extraction-review mapping context mapping-review; do
  .venv/bin/compare-pipeline --repo . run \
    --campaign-id CAMPAIGN-KNFSD-V73-001 \
    --partition development --stage "$stage" --max-jobs 40 --workers 8
done

.venv/bin/compare-pipeline --repo . run \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --partition development --stage pattern --max-jobs 40 --workers 4

.venv/bin/compare-pipeline --repo . run \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --partition development --stage codeql-fast-author --max-jobs 40 --workers 4

.venv/bin/compare-pipeline --repo . run \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --partition development --stage codeql-fast-gate --max-jobs 40
```

`--max-jobs` bounds the number of new case outputs created by one resumable
invocation. `--workers` bounds concurrent isolated Codex processes; it does
not create shared sessions or bypass partition access checks. Start with four
pattern workers and never exceed eight total workers.

`context` is deterministic and verifies an exact clean v7.3 source tree. Mapping review, not the mapper proposal, decides KNFSD applicability.
`codeql-fast-author` creates the rule plan, query, and qltests in one isolated
job. It accepts either a proposed or reviewed Pattern IR. The driver authors 16
patterns at a time with four workers and immediately runs `codeql-fast-gate`
for that batch, so deterministic feedback starts before every pattern is
authored. Invalid bundles are quarantined without stopping unrelated patterns.
The gate uses CodeQL compilation and qltest instead of a second LLM review.
Passing rules are accepted and materialized; failures become `needs_revision`
and are the only rules sent to `codeql-author` for a bounded repair. No failed
version is overwritten.

The legacy `pattern-review`, `rule-plan`, and `codeql-review` stages remain
available for an explicitly escalated investigation, but they are not part of
the default Round-0 path.

After all fast gates and bounded repairs, scan the accepted queries together:

```bash
.venv/bin/compare-batch-scan --repo . \
  --campaign-id CAMPAIGN-KNFSD-V73-001 --round 1
```

The batch command invokes `codeql database analyze` once, then splits SARIF
and normalized candidates back into independent per-pattern Round directories.

## 4. One pattern round

Create a round manifest with reviewed inputs, then use this order:

1. `compare-round-pipeline scan`
2. `compare-round-pipeline normalize`
3. `compare-round-pipeline plan-validation` with the campaign's private split manifest
4. `compare-round-pipeline validate-runtime --sanitizer kasan`
5. `compare-round-pipeline validate-runtime --sanitizer kcsan`
6. `compare-round-pipeline adjudicate`
7. `compare-round-pipeline close`
8. `compare-round-pipeline refine`

KCSAN jobs request 100 effective target-reached executions. Attempts that miss the target do not count toward 100.

For a resumable end-to-end fast campaign, use:

```bash
.venv/bin/compare-campaign-driver --repo . \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --workers 8 --pattern-workers 4 --max-repair-rounds 3 --round 1
```

The driver never feeds Validation or Sealed Holdout inputs to rule generation
or repair. It completes Development fast gates and the batch scan before it
starts those partitions.

## 5. Evaluation and promotion

Run known-positive vulnerable/patched controls on Development and Validation without exposing their case details to the generator. Run Sealed Holdout only at a milestone. Feed the resulting evaluation summaries to `compare-promotion`.

If the decision is `refine`, create the next Pattern IR and rule plan. If it is `throttle` or `quarantine`, stop that rule variant while preserving every artifact. Promotion never deletes earlier rule versions.

## 6. Recovery

- Re-run the same stage; existing successful artifacts are skipped.
- A changed bound input hash is an error, not an invitation to overwrite the round.
- Failed Codex jobs keep `.audit.json` with stderr tail and exact prompt/schema hashes.
- Runtime capability gaps stay in the round and are excluded from FP counts.
