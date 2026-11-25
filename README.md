# claude-code-security

Security-first [Claude Code](https://docs.claude.com/en/docs/claude-code) configuration for regulated environments — fintech, healthtech, and any enterprise where "the AI can edit files and run commands" needs a security story.

This repo gives you four things you can drop into a project (or deploy org-wide through managed settings):

| Control | What it does | Where |
| --- | --- | --- |
| **Audit hook** | Appends a tamper-evident JSON record for every file write, edit and shell command | [`audit-log.sh`](.claude/hooks/audit-log.sh) |
| **Boundary hook** | Blocks edits outside the project directory, through `../` or symlinks, and blocks edits to the controls themselves | [`enforce-boundaries.sh`](.claude/hooks/enforce-boundaries.sh) |
| **Secret-detection hook** | Blocks writes and commands that contain credentials, without echoing them | [`block-secrets.sh`](.claude/hooks/block-secrets.sh) |
| **Locked-down settings** | Minimal `permissions` footprint, bypass mode disabled, secrets and network tools denied | [`.claude/settings.json`](.claude/settings.json) |

> **Read [`docs/threat-model.md`](docs/threat-model.md) before relying on this.** Hooks are strong guardrails, not a sandbox. They do not make Claude Code "compliant" by themselves — they produce controls and evidence your security team can build on.

## Install

Requires `bash` and [`jq`](https://jqlang.github.io/jq/) on macOS or Linux (use WSL on Windows). The hooks **fail closed**: if `jq` is missing, they block rather than silently doing nothing.

```bash
# from the root of the project you want to protect
cp -r <this-repo>/.claude/hooks .claude/hooks
cp <this-repo>/.claude/settings.json .claude/settings.json    # or merge into your existing file
chmod +x .claude/hooks/*.sh
```

Then start Claude Code in the project and confirm the hooks are registered with `/hooks`.

For organization-wide enforcement that engineers cannot override locally, deploy through managed settings instead — see [`docs/managed-settings.md`](docs/managed-settings.md).

## What gets blocked

| Action | Result |
| --- | --- |
| Write/edit containing an AWS key, private key, GitHub/Slack/Stripe token, LLM API key, JWT, credentialed URL, or a quoted `api_key`/`secret`/`password` literal | Blocked, logged as `deny`; the value is never printed or logged |
| Write/edit to `/etc/passwd`, `../outside`, or a symlink that points out of the project | Blocked, logged |
| Write/edit to `.git/`, `.claude/hooks/`, `.claude/settings*.json` | Blocked — only a human can change the controls |
| Shell command containing a secret (e.g. `export TOKEN=ghp_…`) | Blocked, logged redacted |
| Read of `.env*`, `*.pem`, `~/.ssh`, `~/.aws`, … | Denied by `settings.json` |
| `curl`, `wget`, `ssh`, `sudo`, `rm -rf`, `git push`, web fetch/search | Denied by `settings.json` |

Documented fake values can be allowed by adding `secret-scan:ignore` to the same line.

## Audit log

Records go to `~/.claude/audit/audit-YYYY-MM-DD.jsonl` (override with `CLAUDE_AUDIT_DIR`). One line per event:

```json
{"schema":1,"ts":"2026-01-15T14:02:11Z","event":"post_tool_use","decision":"allow","user":"asmith","host":"dev-42","session_id":"…","project":"/work/claims-api","tool":"Write","path":"src/app.py","file_sha256":"9f86d0…","prev_sha256":"4b2f1c…"}
```

It stores metadata and a hash of the resulting file — **never file contents**. Each record includes the SHA-256 of the previous line; verify a file with:

```bash
scripts/verify-audit-log.sh ~/.claude/audit/audit-2026-01-15.jsonl
```

Full schema, retention guidance and control mapping: [`docs/audit-log-format.md`](docs/audit-log-format.md).

## Test

```bash
bash tests/run.sh
```

40 behavioural tests: secrets (including edits, multi-edits and shell commands), boundary escapes (traversal, symlink, prefix-sibling, case-folding), log integrity (including tamper detection), and fail-closed behaviour. CI runs them with `shellcheck`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `CLAUDE_AUDIT_DIR` | `~/.claude/audit` | Where audit logs are written |
| `CLAUDE_ALLOWED_DIRS` | *(empty)* | Colon-separated extra directories Claude may edit |
| `CLAUDE_SECRET_PATTERNS` | `.claude/hooks/secret-patterns.txt` | Alternative pattern file |

Add your organization's own token formats to [`secret-patterns.txt`](.claude/hooks/secret-patterns.txt) (`name::extended-regex`).

## Related

- [`claude-code-org-setup`](https://github.com/ivandir/claude-code-org-setup) — org-wide CLAUDE.md, permission presets and rollout guide. Start there; add this repo for regulated environments.

## License

[MIT](LICENSE)
