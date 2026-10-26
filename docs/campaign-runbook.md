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

## 3. Development roles

Run and inspect each stage before advancing:

```bash
for stage in extraction extraction-review mapping context mapping-review; do
  .venv/bin/compare-pipeline --repo . run \
    --campaign-id CAMPAIGN-KNFSD-V73-001 \
    --partition development --stage "$stage" --max-jobs 40 --workers 8
done

for stage in pattern pattern-review rule-plan codeql-author codeql-review codeql-materialize; do
  .venv/bin/compare-pipeline --repo . run \
    --campaign-id CAMPAIGN-KNFSD-V73-001 \
    --partition development --stage "$stage" --max-jobs 5
done
```

`--max-jobs` bounds the number of new case outputs created by one resumable
invocation. `--workers` bounds concurrent case-level Codex processes; it does
not create shared sessions or bypass partition access checks. Start with four
workers, increase only after a small successful batch, and keep pattern/rule
stages serial.

`context` is deterministic and verifies an exact clean v7.3 source tree. Mapping review, not the mapper proposal, decides KNFSD applicability.
Before `codeql-review` calls the independent reviewer, it materializes the
proposed artifact in a content-hash preflight directory and supplies the real
CodeQL compile and qltest report. Only a reviewed artifact with `accepted`
status can enter the final materialization and scan gates.
If review returns `needs_revision`, run `codeql-author` again. A `rejected`
artifact is quarantined and requires an explicit new design decision rather
than an automatic retry.
The pipeline passes the prior artifact, review, and preflight report into a new
`codeql-vN.json`, then `codeql-review` reviews that exact version. Repeat until
accepted; no failed version is overwritten.

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

## 5. Evaluation and promotion

Run known-positive vulnerable/patched controls on Development and Validation without exposing their case details to the generator. Run Sealed Holdout only at a milestone. Feed the resulting evaluation summaries to `compare-promotion`.

If the decision is `refine`, create the next Pattern IR and rule plan. If it is `throttle` or `quarantine`, stop that rule variant while preserving every artifact. Promotion never deletes earlier rule versions.

## 6. Recovery

- Re-run the same stage; existing successful artifacts are skipped.
- A changed bound input hash is an error, not an invitation to overwrite the round.
- Failed Codex jobs keep `.audit.json` with stderr tail and exact prompt/schema hashes.
- Runtime capability gaps stay in the round and are excluded from FP counts.
