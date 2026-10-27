#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

.venv/bin/python -m compileall -q src tests
.venv/bin/python -m pytest -q
.venv/bin/compare-validate --repo "$repo_dir"
.venv/bin/python scripts/prepush_audit.py "$repo_dir"

codeql_bin="external/codeql-v2.27.3/codeql"
if [[ -d "$codeql_bin" ]]; then
  codeql_bin="$codeql_bin/codeql"
fi
if [[ -x "$codeql_bin" ]]; then
  "$codeql_bin" pack install codeql/knfsd-rules
  while IFS= read -r query; do
    "$codeql_bin" query compile "$query"
  done < <(find codeql/knfsd-rules -maxdepth 1 -name '*.ql' -type f | sort)
  "$codeql_bin" test run codeql/knfsd-rules/tests
else
  echo "SKIP: pinned CodeQL CLI is not installed"
fi
