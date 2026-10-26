#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness_dir="$repo_dir/external/knfsd-syzkaller"
remote_url="https://github.com/Tobabz/knfsd-syzkaller.git"
pinned_commit="1000ed686ed639617d568cfe4111f80ba2ad7e89"
overlays=(
  "$repo_dir/patches/knfsd-syzkaller-v7.3-base.patch"
  "$repo_dir/patches/knfsd-syzkaller-tcg-runtime.patch"
)

mkdir -p "$repo_dir/external"
if [[ ! -d "$harness_dir/.git" ]]; then
  gh repo clone Tobabz/knfsd-syzkaller "$harness_dir"
fi

actual_origin="$(git -C "$harness_dir" remote get-url origin)"
case "$actual_origin" in
  "$remote_url"|https://github.com/Tobabz/knfsd-syzkaller|git@github.com:Tobabz/knfsd-syzkaller.git) ;;
  *) printf 'Unexpected harness origin: %s\n' "$actual_origin" >&2; exit 2 ;;
esac

if ! git -C "$harness_dir" cat-file -e "${pinned_commit}^{commit}" 2>/dev/null; then
  git -C "$harness_dir" fetch --depth=1 origin "$pinned_commit"
fi

head="$(git -C "$harness_dir" rev-parse HEAD)"
if [[ "$head" != "$pinned_commit" ]]; then
  if [[ -n "$(git -C "$harness_dir" status --porcelain)" ]]; then
    printf 'Refusing to move a dirty harness checkout: %s\n' "$harness_dir" >&2
    exit 2
  fi
  git -C "$harness_dir" checkout --detach "$pinned_commit"
fi

for overlay in "${overlays[@]}"; do
  if git -C "$harness_dir" apply --check "$overlay" 2>/dev/null; then
    git -C "$harness_dir" apply "$overlay"
  elif ! git -C "$harness_dir" apply --reverse --check "$overlay" 2>/dev/null; then
    printf 'Harness overlay is neither applicable nor already applied: %s\n' "$overlay" >&2
    exit 2
  fi
done

base_file="$harness_dir/bundle/patches/BASE"
if ! grep -qx 'kernel_tag=v7.3' "$base_file" || \
   ! grep -qx 'kernel_commit=c03c1a14507dfaf8b856c2608f9ac216021fc222' "$base_file"; then
  printf 'Harness v7.3 BASE overlay did not produce the required pin.\n' >&2
  exit 2
fi

unexpected="$(git -C "$harness_dir" status --porcelain | \
  grep -Ev '^ M (bundle/patches/BASE|bundle/baker/bake_nfs_protocol_image.py|tools/bootstrap-kcov-env.py)$' || true)"
if [[ -n "$unexpected" ]]; then
  printf 'Harness has changes outside the expected v7.3 BASE overlay:\n%s\n' "$unexpected" >&2
  exit 2
fi

printf 'Harness pinned: %s @ %s\n' "$harness_dir" "$(git -C "$harness_dir" rev-parse HEAD)"
printf 'Kernel BASE pinned: v7.3 @ c03c1a14507dfaf8b856c2608f9ac216021fc222\n'
printf 'Next: .venv/bin/compare-runtime-status --repo %s\n' "$repo_dir"
