#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

command -v codex
codex --version
codex login status
.venv/bin/compare-codex-job extractor \
  --input tests/fixtures/minimal-case.json \
  --output runs/smoke/extraction.json \
  --repo "$repo_dir" \
  --dry-run
