# Repository instructions

- Treat `data/raw/` as immutable source evidence.
- Never write LLM conclusions into `data/cases/`; put them in versioned analysis artifacts.
- Use the controlled identifiers in `registry/` for NFS semantics and vulnerability taxonomy.
- Preserve raw evidence, hashes, model configuration, prompt hashes, and output-schema hashes for every run.
- Do not label missing sanitizer output as a false positive.
- Do not expose Validation or Sealed Holdout case details to generator or refiner jobs.
- Target NFSv3, v4.0, v4.1, and v4.2 only. NFSv2 source cases remain preserved but must not enter active KNFSd mappings, rules, or runtime jobs.
- Run headless LLM roles through `compare-codex-job`; do not silently change the configured model or reasoning effort.
- Do not commit CodeQL databases, kernel builds, VM images, credentials, or large raw logs.
