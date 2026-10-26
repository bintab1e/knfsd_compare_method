# Evidence and verdict policy

## Mapping gate

An active mapping requires an equivalent KNFSD v7.3 remote NFS/RPC feature, a plausible remote path, and a transferable root cause or invariant. Preserve `not_applicable` and `insufficient_evidence` records, but do not generate Pattern IR or CodeQL from them.

## Collection and mirrors

Keep the canonical source URL in every manifest. Fetch only HTTPS URLs on the
reviewed host allowlist, with public-address, content-type, timeout, redirect,
and size checks. When the execution host cannot route to `git.kernel.org`, a
recognized commit URL may be fetched from the content-addressed official
GitHub mirror (`torvalds/linux` or `gregkh/linux`) using the same commit hash;
record that mirror as `final_url`. Never use a search result or an unpinned
branch page as a patch substitute.

## Candidate terminal states

- `confirmed_tp`
- `confirmed_fp`
- `inconclusive`
- `unreached`
- `harness_gap`
- `no_signal`
- `no_signal_after_100`
- `insufficient_runs`
- `duplicate`

Only a proved semantic mismatch, a proved safe guard, or a proved lack of remote path may become `confirmed_fp`. Lack of sanitizer output is never enough.

## Sanitizer evidence

A relevant reproducible KASAN report connected to the candidate path is strong TP evidence. Recheck findings observed with custom remote-KCOV patches on a v7.3 KASAN confirmation build without those custom observation patches.

A relevant KCSAN report confirms a data race, but the security impact may remain unknown. Count only effective KCSAN runs that reach the target and exercise the concurrent window. One hundred effective runs without a report yield `no_signal_after_100`, not FP.

## Rule refinement

Refiners may use Development confirmed TP and confirmed FP as hard examples. They may not consume Validation or Sealed Holdout case details or outcomes. Keep unknown, no-signal, reachability-gap, and harness-gap cases separate. Preserve all previous TP, prefer improved generalization, and use quarantine instead of deleting noisy rule variants.

## Promotion

Preserve every existing confirmed TP. Require either a new TP or fewer confirmed FP, no Validation regression, bounded candidate/runtime growth, and a passing milestone Holdout check when one is scheduled. Holdout outcomes never become feedback for a later generation or refinement job.
