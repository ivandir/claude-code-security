#!/usr/bin/env bash
# PreToolUse hook for file-editing tools.
#   1. Blocks edits outside the project directory (plus any dirs in CLAUDE_ALLOWED_DIRS, colon-separated).
#   2. Blocks edits to the security controls themselves: .git, .claude/hooks, .claude/settings*.json.
# Symlinks are resolved where realpath supports it, so a link pointing outside the project is caught.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_jq
shopt -s nocasematch   # case-insensitive filesystems (macOS, Windows)

input=$(cat)
path=$(tool_path "$input")
[[ -z $path ]] && exit 0

cwd=$(jq -r '.cwd // empty' <<<"$input")
cwd=${cwd:-$PWD}
project=$(abs_path "${CLAUDE_PROJECT_DIR:-$cwd}" "$cwd")
target=$(abs_path "$path" "$cwd")

deny() {
  audit_write pre_tool_use deny "$1" "$input"
  echo "Blocked by claude-code-security: $1" >&2
  exit 2
}

inside() { [[ $1 == "$2" || $1 == "$2"/* ]]; }

allowed=false
if inside "$target" "$project"; then allowed=true; fi
IFS=: read -ra extra <<<"${CLAUDE_ALLOWED_DIRS:-}"
for d in "${extra[@]:-}"; do
  if [[ -n $d ]] && inside "$target" "$(abs_path "$d" "$cwd")"; then allowed=true; fi
done
if [[ $allowed != true ]]; then
  deny "'$path' is outside the project directory ($project)."
fi

rel=${target#"$project"/}
case "$rel" in
  .git|.git/*)
    deny "'$rel' is protected (git internals)." ;;
  .claude/hooks|.claude/hooks/*|.claude/settings.json|.claude/settings.local.json)
    deny "'$rel' is a security control and can only be changed by a human, outside Claude Code." ;;
esac
exit 0
