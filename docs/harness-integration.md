# KNFSd runtime harness integration

## Pinned inputs

- Harness repository: `https://github.com/Tobabz/knfsd-syzkaller.git`
- Harness commit: `1000ed686ed639617d568cfe4111f80ba2ad7e89`
- Linux tag: `v7.3`
- Linux tag commit: `c03c1a14507dfaf8b856c2608f9ac216021fc222`
- Syzkaller commit declared by the harness: `801f0966669a37e048adabf9e5f38ce52825ea82`

`scripts/sync_runtime_harness.sh` recreates this binding. The external checkout and build products remain ignored; the repository tracks the source pin, v7.3 BASE overlay, expected artifact paths, and readiness checks.

## v7.3 apply test

On 2026-10-25, the harness `tools/bump-kernel.py v7.3 --keep` workflow shallow-cloned final Linux v7.3 and applied all six checked-in kernel patches with `git am -3`. Every patch applied without conflict:

1. Per-program remote KCOV request generations.
2. SUNRPC lane attribution.
3. NFSD asynchronous COPY attribution.
4. NFSv4.1 callback attribution.
5. KCOV sibling-call filtering.
6. lockd/NLM attribution.

Only `bundle/patches/BASE` changed. The reproducible change is stored in `patches/knfsd-syzkaller-v7.3-base.patch`.

## Campaign boundary

- Included protocols: NFSv3, v4.0, v4.1, v4.2.
- Excluded protocol: NFSv2.
- Sanitizers: separate KASAN and KCSAN images.
- KCSAN: at most 100 effective target-reached concurrent executions per candidate.
- Remote coverage: required for KNFSd campaigns.

## Verified runtime state

The harness bootstrap produced `runtime/knfsd-v7.3/manifest.json` for exact tag `v7.3` and base commit `c03c1a14507dfaf8b856c2608f9ac216021fc222`. Separate KASAN and KCSAN kernels booted with the baked fixture and passed sanitizer/fixture verification. `compare-runtime-status` verifies the manifest, hashes, harness pin, overlay base, and required artifacts before returning `runtime_ready: true`.

The pinned syzkaller strict-parser bundle is generated locally from the same patched syzkaller tree and remains an ignored external artifact. Generic Stage 1 jobs still require a host-generated `validation/stage1.json`; when that deployment is absent, `compare-runtime-dispatch` records `harness_gap`. Exact built-in RPC templates remain available independently.
