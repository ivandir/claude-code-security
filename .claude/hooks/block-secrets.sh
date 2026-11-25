#!/usr/bin/env bash
# PreToolUse hook: block writes and shell commands that contain secrets.
# Exit 2 blocks the tool call and shows stderr to Claude. The matched value is never printed.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_jq

input=$(cat)
text=$(tool_text "$input")
[[ -z $text ]] && exit 0

matches=$(printf '%s\n' "$text" | secret_matches)
if [[ -n $matches ]]; then
  names=$(tr '\n' ',' <<<"$matches")
  names=${names%,}
  tool=$(jq -r '.tool_name // "tool call"' <<<"$input")
  audit_write pre_tool_use deny "possible secret detected: $names" "$input"
  {
    echo "Blocked by claude-code-security: this $tool contains what looks like a secret ($names)."
    echo "Do not write credentials into files or commands. Read them from an environment variable"
    echo "or a secrets manager instead. If this is a documented fake value, add 'secret-scan:ignore'"
    echo "to the same line."
  } >&2
  exit 2
fi
exit 0
