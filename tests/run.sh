#!/usr/bin/env bash
# Behavioural tests for the hooks. Usage: bash tests/run.sh   (needs bash + jq)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS="$ROOT/.claude/hooks"
command -v jq >/dev/null || { echo "jq is required to run the tests" >&2; exit 2; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export CLAUDE_AUDIT_DIR="$TMP/audit"
export CLAUDE_PROJECT_DIR="$TMP/project"
mkdir -p "$CLAUDE_PROJECT_DIR/src" "$TMP/outside"
ln -s "$TMP/outside" "$CLAUDE_PROJECT_DIR/escape"

pass=0; fail=0

mk() { # mk <tool> <tool_input-json>
  jq -cn --arg tool "$1" --argjson ti "$2" --arg cwd "$CLAUDE_PROJECT_DIR" \
    '{session_id: "test-session", cwd: $cwd, tool_name: $tool, tool_input: $ti}'
}

expect() { # expect <name> <want-exit> <hook> <input-json>
  local name=$1 want=$2 hook=$3 input=$4 got err
  err=$(printf '%s' "$input" | bash "$HOOKS/$hook" 2>&1 >/dev/null); got=$?
  if [[ $got -eq $want ]]; then
    pass=$((pass + 1)); echo "  ok    $name"
  else
    fail=$((fail + 1)); echo "  FAIL  $name (want exit $want, got $got)"; [[ -n $err ]] && echo "        $err"
  fi
  LAST_ERR=$err
}

# Fake credentials assembled at runtime so this file never contains a literal match.
AWS_KEY="AKIA""IOSFODNN7EXAMPLE"
GH_TOKEN="ghp_""$(printf 'a%.0s' {1..36})"

echo "block-secrets.sh"
expect "blocks AWS key in Write"            2 block-secrets.sh "$(mk Write "$(jq -cn --arg c "key = \"$AWS_KEY\"" '{file_path:"src/a.py",content:$c}')")"
expect "blocks GitHub token in Edit"        2 block-secrets.sh "$(mk Edit "$(jq -cn --arg c "$GH_TOKEN" '{file_path:"src/a.py",old_string:"x",new_string:$c}')")"
expect "blocks private key header"          2 block-secrets.sh "$(mk Write '{"file_path":"k.txt","content":"-----BEGIN RSA PRIVATE KEY-----\nabc"}')"
expect "blocks secret in MultiEdit"         2 block-secrets.sh "$(mk MultiEdit "$(jq -cn --arg c "$AWS_KEY" '{file_path:"a",edits:[{old_string:"a",new_string:"b"},{old_string:"c",new_string:$c}]}')")"
expect "blocks secret in Bash command"      2 block-secrets.sh "$(mk Bash "$(jq -cn --arg c "export TOKEN=$GH_TOKEN" '{command:$c}')")"
expect "blocks password in connection URL"  2 block-secrets.sh "$(mk Write '{"file_path":"a","content":"postgres://app:hunter2hunter2@db.internal/x"}')"
expect "blocks quoted api key assignment"   2 block-secrets.sh "$(mk Write '{"file_path":"a","content":"api_key = \"abcdefghijklmnopqrstuvwxyz123456\""}')"
expect "allows normal code"                 0 block-secrets.sh "$(mk Write '{"file_path":"a","content":"def add(a, b):\n    return a + b"}')"
expect "allows env var reference"           0 block-secrets.sh "$(mk Write '{"file_path":"a","content":"key = os.environ[\"API_KEY\"]"}')"
expect "honours secret-scan:ignore"         0 block-secrets.sh "$(mk Write "$(jq -cn --arg c "k = \"$AWS_KEY\" # secret-scan:ignore" '{file_path:"a",content:$c}')")"
expect "allows tool calls with no text"     0 block-secrets.sh "$(mk Read '{"file_path":"a"}')"
expect "blocks and masks (stderr check)"    2 block-secrets.sh "$(mk Write "$(jq -cn --arg c "$AWS_KEY" '{file_path:"a",content:$c}')")"
if grep -q "$AWS_KEY" <<<"$LAST_ERR"; then fail=$((fail + 1)); echo "  FAIL  secret value leaked to stderr"; else pass=$((pass + 1)); echo "  ok    secret value not printed"; fi

echo "enforce-boundaries.sh"
expect "allows file inside project"         0 enforce-boundaries.sh "$(mk Write '{"file_path":"src/app.py","content":"x"}')"
expect "allows absolute path inside"        0 enforce-boundaries.sh "$(mk Write "$(jq -cn --arg p "$CLAUDE_PROJECT_DIR/src/app.py" '{file_path:$p,content:"x"}')")"
expect "blocks absolute path outside"       2 enforce-boundaries.sh "$(mk Write '{"file_path":"/etc/passwd","content":"x"}')"
expect "blocks ../ traversal"               2 enforce-boundaries.sh "$(mk Edit '{"file_path":"../outside/x.txt","old_string":"a","new_string":"b"}')"
expect "blocks symlink escape"              2 enforce-boundaries.sh "$(mk Write '{"file_path":"escape/x.txt","content":"x"}')"
expect "blocks sibling dir with same prefix" 2 enforce-boundaries.sh "$(mk Write "$(jq -cn --arg p "$CLAUDE_PROJECT_DIR-evil/x" '{file_path:$p,content:"x"}')")"
expect "blocks .git internals"              2 enforce-boundaries.sh "$(mk Write '{"file_path":".git/config","content":"x"}')"
expect "blocks editing hooks"               2 enforce-boundaries.sh "$(mk Edit '{"file_path":".claude/hooks/block-secrets.sh","old_string":"a","new_string":"b"}')"
expect "blocks editing settings.json"       2 enforce-boundaries.sh "$(mk Write '{"file_path":".claude/settings.json","content":"{}"}')"
expect "blocks hooks via mixed case"        2 enforce-boundaries.sh "$(mk Write '{"file_path":".Claude/Hooks/x.sh","content":"x"}')"
expect "blocks notebook outside project"    2 enforce-boundaries.sh "$(mk NotebookEdit '{"notebook_path":"/tmp/n.ipynb","new_source":"x"}')"
CLAUDE_ALLOWED_DIRS="$TMP/outside" expect "CLAUDE_ALLOWED_DIRS opens a dir" 0 enforce-boundaries.sh "$(mk Write "$(jq -cn --arg p "$TMP/outside/ok.txt" '{file_path:$p,content:"x"}')")"

echo "audit-log.sh + verify-audit-log.sh"
rm -rf "$CLAUDE_AUDIT_DIR"
echo "hello" > "$CLAUDE_PROJECT_DIR/src/app.py"
expect "records a file write"               0 audit-log.sh "$(mk Write '{"file_path":"src/app.py","content":"hello"}')"
expect "records a command (redacted)"       0 audit-log.sh "$(mk Bash "$(jq -cn --arg c "deploy --token $GH_TOKEN" '{command:$c}')")"
expect "records a denial"                   2 enforce-boundaries.sh "$(mk Write '{"file_path":"/etc/shadow","content":"x"}')"
LOG=$(ls "$CLAUDE_AUDIT_DIR"/audit-*.jsonl 2>/dev/null | head -n 1)
check() { if eval "$2"; then pass=$((pass + 1)); echo "  ok    $1"; else fail=$((fail + 1)); echo "  FAIL  $1"; fi; }
check "log file created"                    '[[ -f $LOG ]]'
check "every line is valid JSON"            'jq -e . "$LOG" >/dev/null'
check "three records written"               '[[ $(wc -l < "$LOG") -eq 3 ]]'
check "file hash matches the file"          '[[ $(jq -r "select(.tool==\"Write\") | .file_sha256" "$LOG" | head -n 1) == $(sha256sum "$CLAUDE_PROJECT_DIR/src/app.py" | cut -d" " -f1) ]]'
check "command is redacted in the log"      '! grep -q "$GH_TOKEN" "$LOG" && grep -q "REDACTED:github-token" "$LOG"'
check "denial recorded with reason"         'jq -e "select(.decision==\"deny\") | .reason" "$LOG" >/dev/null'
check "file contents never logged"          '! grep -q "\"content\"" "$LOG"'
check "verify passes on intact log"         'bash "$ROOT/scripts/verify-audit-log.sh" "$LOG" >/dev/null'
sed -i '2s/"user":"[^"]*"/"user":"mallory"/' "$LOG"
check "verify detects a tampered record"    '! bash "$ROOT/scripts/verify-audit-log.sh" "$LOG" >/dev/null'

echo "fail-closed behaviour"
NOJQ="$TMP/nojq"; mkdir -p "$NOJQ"
for b in bash dirname cat; do ln -s "$(command -v $b)" "$NOJQ/$b"; done
for hook in block-secrets.sh enforce-boundaries.sh audit-log.sh; do
  printf '%s' "$(mk Write '{"file_path":"a","content":"x"}')" | env PATH="$NOJQ" "$NOJQ/bash" "$HOOKS/$hook" >/dev/null 2>&1; got=$?
  if [[ $got -eq 2 ]]; then pass=$((pass + 1)); echo "  ok    $hook blocks when jq is missing"; else fail=$((fail + 1)); echo "  FAIL  $hook should exit 2 without jq, got $got"; fi
done

echo
echo "passed: $pass   failed: $fail"
[[ $fail -eq 0 ]]
