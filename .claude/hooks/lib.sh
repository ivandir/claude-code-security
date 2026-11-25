#!/usr/bin/env bash
# Shared helpers for the claude-code-security hooks. Source this file; do not execute it.
# Requires: bash, jq, and sha256sum or shasum. POSIX systems only (use WSL on Windows).

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERN_FILE="${CLAUDE_SECRET_PATTERNS:-$HOOK_DIR/secret-patterns.txt}"
AUDIT_DIR="${CLAUDE_AUDIT_DIR:-$HOME/.claude/audit}"

# Fail closed: a security hook that silently does nothing is worse than one that stops work.
require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "claude-code-security: 'jq' is required but not installed. Blocking (fail closed)." >&2
    exit 2
  fi
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# Path a tool call targets (empty if none).
tool_path() {
  jq -r '.tool_input.file_path // .tool_input.notebook_path // ""' <<<"$1"
}

# Everything a tool call is about to write or run, as one string.
tool_text() {
  jq -r '[.tool_input.content, .tool_input.new_string, .tool_input.new_source, .tool_input.command,
          ((.tool_input.edits // [])[] | .new_string)]
         | map(select(. != null)) | join("\n")' <<<"$1"
}

# Normalised absolute path. Resolves symlinks when GNU/BSD realpath supports -m,
# otherwise collapses "." and ".." lexically.
abs_path() {
  local p=$1 base=$2
  [[ $p == /* ]] || p="$base/$p"
  if realpath -m / >/dev/null 2>&1; then
    realpath -m -- "$p"
    return
  fi
  local -a out=()
  local seg IFS=/
  for seg in $p; do
    case $seg in
      ''|.) ;;
      ..) if [[ ${#out[@]} -gt 0 ]]; then unset 'out[${#out[@]}-1]'; fi ;;
      *) out+=("$seg") ;;
    esac
  done
  printf '/%s' "${out[@]}"
}

# stdin: text. stdout: names of every secret pattern that matches.
# Lines containing "secret-scan:ignore" are skipped (for documented fake values).
secret_matches() {
  local text line name re
  text=$(grep -v 'secret-scan:ignore' || true)
  while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    name=${line%%::*}
    re=${line#*::}
    if grep -Eq -e "$re" <<<"$text"; then
      echo "$name"
    fi
  done < "$PATTERN_FILE"
}

# Replace anything matching a secret pattern so it never reaches the audit log.
redact() {
  local s=$1 line name re
  while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    name=${line%%::*}
    re=${line#*::}
    s=$(sed -E "s~${re}~[REDACTED:${name}]~g" <<<"$s")
  done < "$PATTERN_FILE"
  printf '%s' "$s"
}

# audit_write <event> <decision> <reason> <hook-input-json>
# Appends one JSON line to a per-day log. Each record carries the SHA-256 of the
# previous line, so edits to the middle of the log are detectable (see scripts/verify-audit-log.sh).
audit_write() {
  local event=$1 decision=$2 reason=$3 input=$4
  local ts user host cwd project path cmd fsha file prev

  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  user=${USER:-$(id -un)}
  host=$(hostname)
  cwd=$(jq -r '.cwd // empty' <<<"$input")
  cwd=${cwd:-$PWD}
  project=${CLAUDE_PROJECT_DIR:-$cwd}
  path=$(tool_path "$input")
  cmd=$(jq -r '.tool_input.command // ""' <<<"$input")
  cmd=$(redact "$cmd")
  cmd=${cmd:0:500}

  fsha=""
  if [[ $event == post_tool_use && -n $path ]]; then
    local abs
    abs=$(abs_path "$path" "$cwd")
    if [[ -f $abs ]]; then fsha=$(sha256_stdin < "$abs"); fi
  fi

  mkdir -p "$AUDIT_DIR"
  chmod 700 "$AUDIT_DIR" 2>/dev/null || true
  file="$AUDIT_DIR/audit-$(date -u +%Y-%m-%d).jsonl"

  (
    if command -v flock >/dev/null 2>&1; then flock 9; fi
    prev="genesis"
    if [[ -s $file ]]; then prev=$(tail -n 1 "$file" | sha256_stdin); fi
    jq -cn --argjson in "$input" \
      --arg ts "$ts" --arg event "$event" --arg decision "$decision" --arg reason "$reason" \
      --arg user "$user" --arg host "$host" --arg project "$project" \
      --arg path "$path" --arg cmd "$cmd" --arg fsha "$fsha" --arg prev "$prev" '
      {schema: 1, ts: $ts, event: $event, decision: $decision, reason: $reason,
       user: $user, host: $host, session_id: ($in.session_id // ""), project: $project,
       tool: ($in.tool_name // ""), path: $path, command: $cmd, file_sha256: $fsha,
       prev_sha256: $prev}
      | with_entries(select(.value != "" or .key == "prev_sha256"))' >> "$file"
  ) 9>>"$file.lock"
}
