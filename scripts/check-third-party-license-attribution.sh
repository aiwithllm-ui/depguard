#!/usr/bin/env bash
# Compare cargo-about notices while canonicalizing only simple SPDX OR terms.
# Every other byte, including crate/version/source/license-text content, remains
# subject to the ordinary unified diff below.
set -euo pipefail

normalize_spdx_or_terms() {
  perl -0pe '
    s{(<td>)([A-Za-z0-9.+-]+(?: OR [A-Za-z0-9.+-]+)+)(</td>)}
      {$1 . join(" OR ", sort { $a cmp $b } split(/ OR /, $2)) . $3}ge;
  '
}

if [[ "${1:-}" == "--self-test" ]]; then
  expected='<td>Apache-2.0 OR ISC OR MIT</td>'
  reordered='<td>Apache-2.0 OR MIT OR ISC</td>'
  diff --unified=3 \
    <(printf '%s\n' "$expected" | normalize_spdx_or_terms) \
    <(printf '%s\n' "$reordered" | normalize_spdx_or_terms)

  changed='<td>Apache-2.0 OR BSD-3-Clause OR MIT</td>'
  if diff --brief \
    <(printf '%s\n' "$expected" | normalize_spdx_or_terms) \
    <(printf '%s\n' "$changed" | normalize_spdx_or_terms) > /dev/null; then
    echo "a genuine SPDX license-term change was incorrectly accepted" >&2
    exit 1
  fi
  exit 0
fi

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 COMMITTED_NOTICE GENERATED_NOTICE" >&2
  exit 2
fi

comparison_dir="$(mktemp -d "${TMPDIR:-/tmp}/depguard-license-check.XXXXXX")"
trap 'rm -rf "$comparison_dir"' EXIT

normalize_spdx_or_terms < "$1" > "$comparison_dir/committed.html"
normalize_spdx_or_terms < "$2" > "$comparison_dir/generated.html"
diff --unified=3 "$comparison_dir/committed.html" "$comparison_dir/generated.html"
