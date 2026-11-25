# Audit log format

`audit-log.sh` (and the denial paths in the other hooks) append JSON Lines to `${CLAUDE_AUDIT_DIR:-~/.claude/audit}/audit-YYYY-MM-DD.jsonl` (UTC date, directory mode 700).

## Record schema (v1)

| Field | Type | Always present | Description |
| --- | --- | --- | --- |
| `schema` | int | ✓ | Format version (`1`) |
| `ts` | string | ✓ | UTC timestamp, ISO 8601 |
| `event` | string | ✓ | `post_tool_use` (completed) or `pre_tool_use` (blocked before running) |
| `decision` | string | ✓ | `allow` or `deny` |
| `reason` | string | on `deny` | Why it was blocked. Names the rule, never the secret value |
| `user` | string | ✓ | OS user running Claude Code |
| `host` | string | ✓ | Hostname |
| `session_id` | string | usually | Claude Code session ID — join to the session transcript |
| `project` | string | ✓ | Project directory |
| `tool` | string | ✓ | `Write`, `Edit`, `MultiEdit`, `NotebookEdit` or `Bash` |
| `path` | string | file tools | Target path as supplied by the tool call |
| `command` | string | `Bash` | Command text, **redacted** against `secret-patterns.txt` and truncated to 500 characters |
| `file_sha256` | string | `allow` + file exists | SHA-256 of the file *after* the write |
| `prev_sha256` | string | ✓ | SHA-256 of the previous line in the same file (`genesis` for the first) |

File contents and diffs are never logged.

## Integrity

Each record embeds the hash of the line before it. `scripts/verify-audit-log.sh <file>` recomputes the chain and reports the first broken line. This detects modification or removal of records in the middle of a file; it does not detect truncation at the end or deletion of the whole file, and it does not stop an administrator rewriting the entire chain. Use it as a cheap local check, and rely on off-host storage for assurance.

## Shipping logs off-host

Local logs satisfy "we recorded it", not "it could not have been altered". For regulated environments, forward each line as it is written to storage the engineer cannot modify:

- **S3 with Object Lock** (compliance mode) — sync the audit directory on a short interval, or use a log agent (Fluent Bit, Vector, CloudWatch agent) tailing `audit-*.jsonl`.
- **A SIEM** (Splunk, Datadog, Elastic, CloudWatch Logs) — JSON Lines ingest directly; index on `user`, `tool`, `decision`, `project`.
- Alert on `decision = "deny"` events and on gaps in a session's records.

## Retention

Set retention by your regime, not by this repo. Common starting points: 1 year for SOC 2 evidence; 6 years for HIPAA documentation requirements; at least 1 year (3 months immediately available) for PCI DSS. Confirm with your compliance team.

## Useful queries

```bash
# Everything blocked today
jq -c 'select(.decision=="deny")' ~/.claude/audit/audit-$(date -u +%F).jsonl

# Files changed in a session
jq -r 'select(.session_id=="<id>" and .path) | "\(.ts) \(.tool) \(.path) \(.file_sha256)"' ~/.claude/audit/*.jsonl

# Commands run per user
jq -r 'select(.tool=="Bash") | [.user, .command] | @tsv' ~/.claude/audit/*.jsonl
```

## Control mapping (supporting evidence only)

| Requirement area | What the log provides |
| --- | --- |
| Access control / least privilege (SOC 2 CC6.1) | `deny` events show boundary and secret rules enforcing in practice |
| Change tracking (SOC 2 CC8.1) | Per-file write records with resulting hashes, tied to user and session |
| Monitoring (SOC 2 CC7.2) | Structured events for alerting |
| Audit controls (HIPAA §164.312(b)) | Record of activity by an automated system acting for a user |
| Log and monitor access (PCI DSS Req. 10) | Who, what, when, outcome — with integrity checking |
| Logging (ISO 27001:2022 A.8.15) | Activity logs, protected from casual alteration |

This mapping is a starting point for conversation with your auditor, not a statement of compliance.
