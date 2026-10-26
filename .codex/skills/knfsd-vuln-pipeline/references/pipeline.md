# Pipeline stages

Runtime execution is bound by `config/runtime-harness.yaml` to the pinned `Tobabz/knfsd-syzkaller` checkout. Check `compare-runtime-status` before planning or accepting sanitizer evidence. A missing or non-passing exact-v7.3 manifest is a capability gap, not negative vulnerability evidence.

1. Ingest the eight immutable workbooks into one fact-only JSON file per case and a generated JSONL index. Initialize the deterministic KNFSD root-cause-group split and retain only commitments for hidden partitions in the public manifest.
2. Fetch bounded allowlisted source evidence and retain payload hashes plus explicit failures. Authoritative extraction is blocked when no patch/reference payload exists.
3. Extract attacker input, propagation, dangerous operation, missing guard, violated invariant, fix meaning, and evidence references.
4. Independently review extraction claims against source evidence.
5. Map accepted extraction results to the KNFSD v7.3 Target Map and exclude `not_applicable` cases from the active pipeline. Generate a deterministic source context pack for every proposed mapping, then require an independent mapping review before Pattern IR.
6. Cluster accepted Development mappings by NFS semantics, root cause, and violated invariant into versioned Pattern IR.
7. Compile Pattern IR into strict, broad, and experimental CodeQL rule plans and independently reviewed executable artifacts.
8. Compile and qltest rules on positive and safe-negative controls before scanning the full-kernel CodeQL database.
9. Normalize and deduplicate scan results into candidates, then create separate KASAN and KCSAN remote reachability jobs.
10. Dispatch exact RPC templates or the pinned syzkaller Stage 1 harness. KCSAN uses up to 100 effective, target-reached concurrent executions.
11. Build an evidence bundle and obtain an independent structured verdict.
12. Close immutable per-pattern rounds, propose Pattern IR changes from Development confirmed TP and confirmed FP only, test, and promote or quarantine rule variants through deterministic policy.

Campaigns group many pattern rounds. Pattern round numbers and rule versions remain independently versioned.
