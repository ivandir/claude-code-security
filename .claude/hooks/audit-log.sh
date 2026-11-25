#!/usr/bin/env bash
# PostToolUse hook: append a tamper-evident audit record for every file write, edit and shell command.
# Records contain metadata and a SHA-256 of the resulting file, never file contents.
# Shell commands are logged redacted and truncated to 500 characters.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_jq

input=$(cat)
audit_write post_tool_use allow "" "$input"
exit 0
