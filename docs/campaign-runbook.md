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

.venv/bin/compare-pipeline --repo . run \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --partition development --stage codeql-review --max-jobs 40 --workers 4
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
The deterministic gate records `preflight_passed`, never semantic acceptance.
An independent `codeql-review` decision then verifies the remote entry scope,
transferred invariant, guards/barriers, and realistic controls. Only
`semantically_accepted` rules can scan. Failures become `needs_revision` and
are the only rules sent to `codeql-author` for a bounded repair. No failed
version is overwritten.

The legacy `pattern-review` and separate `rule-plan` stages remain available
for an explicitly escalated investigation. Independent `codeql-review` is a
required default gate.

After deterministic gates and bounded repairs of blocking failures, scan the
preflight-passing queries whose remote KNFSD scope is verified. Semantic
`needs_revision` findings remain visible as `exploratory_preflight` admission;
they do not block this scan and do not confer promotion approval:

```bash
.venv/bin/compare-batch-scan --repo . \
  --campaign-id CAMPAIGN-KNFSD-V73-001 --round 1
```

The batch command binds DB commit/metadata, CodeQL version, scan configuration,
artifact and semantic-review hashes, and every query hash into its output path.
It scans at most 16 queries per chunk. A failed chunk is bisected to quarantine
only the failing query while preserving successful chunk outputs, then SARIF
and normalized candidates are split into independent per-pattern directories.

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

For resumable static preparation, use:

```bash
.venv/bin/compare-static-preparation-driver --repo . \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --workers 8 --pattern-workers 4 --max-repair-rounds 3 --round 1
```

The driver never accesses Sealed Holdout. It completes Development rule gates,
the static batch scan, and Validation data preparation, then reports runtime
validation, adjudication, and promotion as `PENDING`. It is not an end-to-end
runtime campaign.

## 5. Evaluation and promotion

Run known-positive vulnerable/patched controls on Development and Validation without exposing their case details to the generator. Sealed Holdout is evaluated only by a trusted milestone evaluator. The ordinary pipeline rejects it; only a one-time numeric aggregate bound to the public commitment may be released, and that aggregate must not be used as refinement feedback.

```bash
.venv/bin/compare-static-preparation-driver --repo . \
  --campaign-id CAMPAIGN-KNFSD-V73-001 \
  --milestone-holdout \
  --milestone-id MILESTONE-01 \
  --holdout-aggregate /trusted/evaluator/aggregate.json \
  --confirm RELEASE-SEALED-HOLDOUT
```

This command accepts no per-case records and refuses a second release for the
same campaign.

If the decision is `refine`, create the next Pattern IR and rule plan. If it is `throttle` or `quarantine`, stop that rule variant while preserving every artifact. Promotion never deletes earlier rule versions.

## 6. Recovery

- Re-run the same stage; existing successful artifacts are skipped.
- A changed bound input hash is an error, not an invitation to overwrite the round.
- Failed Codex jobs keep `.audit.json` with stderr tail and exact prompt/schema hashes.
- Runtime capability gaps stay in the round and are excluded from FP counts.
