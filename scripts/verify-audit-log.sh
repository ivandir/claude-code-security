#!/usr/bin/env bash
# Verify the hash chain in one or more audit log files.
# Usage: scripts/verify-audit-log.sh ~/.claude/audit/audit-2026-01-15.jsonl [...]
# Detects modified or removed lines in the middle of a file. It cannot detect truncation of the
# newest lines, or deletion of a whole file: ship logs to write-once storage for that (docs/audit-log-format.md).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../.claude/hooks/lib.sh"

[[ $# -ge 1 ]] || { echo "usage: $0 <audit-log.jsonl> [...]" >&2; exit 2; }

status=0
for file in "$@"; do
  prev="genesis"
  n=0
  ok=true
  while IFS= read -r line; do
    n=$((n + 1))
    recorded=$(jq -r '.prev_sha256 // empty' <<<"$line" 2>/dev/null || true)
    if [[ $recorded != "$prev" ]]; then
      echo "FAIL  $file: chain broken at line $n (expected prev=$prev, found ${recorded:-<none>})"
      ok=false
      status=1
      break
    fi
    prev=$(printf '%s\n' "$line" | sha256_stdin)
  done < "$file"
  if [[ $ok == true ]]; then echo "OK    $file ($n records)"; fi
done
exit $status
