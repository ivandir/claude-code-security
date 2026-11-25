# Threat model and limitations

What these controls defend against, and — more importantly — what they do not.

## Assumptions

- The engineer is **not malicious**. The threats are a mistaken, confused, or prompt-injected model, and honest human error.
- Claude Code runs on a managed developer machine or CI runner under the engineer's own account.
- Hooks are loaded from project settings *or* from managed settings. Project-level hooks can be disabled by anyone with write access to the project; only managed settings give you enforcement (see [`managed-settings.md`](managed-settings.md)).

## Threats and controls

| # | Threat | Control | Strength |
| --- | --- | --- | --- |
| T1 | Model writes a credential into a source file or command | `block-secrets.sh` | **Good** for known formats; regex-based, so novel formats and obfuscated values can slip through |
| T2 | Model (or an injected instruction in a file/web page) edits files outside the project — dotfiles, other repos, system files | `enforce-boundaries.sh` | **Good** for the file-edit tools, including `../` and symlink escapes |
| T3 | Model disables the controls by editing hooks or settings | Protected paths in `enforce-boundaries.sh`; `Edit/Write` deny rules; managed settings | **Good** for file tools; see Bash caveat below |
| T4 | Model reads credentials from well-known locations | `Read(...)` deny rules in `settings.json` | **Moderate** — see Bash caveat |
| T5 | Data exfiltration over the network | `curl`/`wget`/`ssh`/`nc`/`scp` and web tools denied | **Moderate** — a shell can use other binaries or language runtimes |
| T6 | Nobody can reconstruct what the model did after an incident | `audit-log.sh` with hash chaining | **Good** for evidence; tamper-*evident*, not tamper-*proof* |
| T7 | Engineer bypasses prompts with `--dangerously-skip-permissions` | `disableBypassPermissionsMode` | **Good** when set in managed settings |

## What this does not do

1. **Bash is not sandboxed.** The boundary hook inspects file-editing tools only. A shell command can write anywhere the OS user can: `python -c "open('/etc/x','w')…"`, `tee`, redirection, `git config --global`. Deny rules on a few commands raise the bar but cannot enumerate every way to write a file. If you need real containment, run Claude Code in a container, VM, or dev environment with a read-only root and no production credentials — then use these hooks as defence in depth.
2. **Secret detection is pattern matching.** It catches common token formats and quoted literals. It will not catch a secret that is split, encoded, or in an unrecognized format, and it can false-positive on high-entropy test data (use `secret-scan:ignore` for those). Pair it with server-side secret scanning (e.g. GitHub push protection) and pre-commit scanners.
3. **The audit log is local and tamper-evident only.** Hash chaining detects edits or deletions in the middle of a file. It does not detect truncation of the newest lines or deletion of a whole file, and an engineer with shell access can rewrite the entire chain. For real assurance, ship logs off-host to write-once storage (S3 Object Lock, a SIEM) as they are written — see [`audit-log-format.md`](audit-log-format.md).
4. **The log records tool calls, not intent or content.** It tells you *that* `src/app.py` changed and its resulting hash — not what the model was asked or what the diff was. Combine with version control and Claude Code's own session transcripts.
5. **Prompt injection is not solved.** These controls limit blast radius if an injected instruction succeeds; they do not stop the model from being influenced. Treat content from the web, tickets, and third-party repos as untrusted.
6. **MCP servers and other tools are out of scope** unless you extend the matchers. Any MCP tool with write access needs its own review and its own hook coverage.
7. **POSIX only.** The scripts need `bash` and `jq`. On Windows use WSL.

## Compliance language

These controls can produce evidence supporting access-control, change-tracking and audit-logging requirements (for example SOC 2 CC6/CC7, HIPAA §164.312(b), PCI DSS Requirement 10, ISO 27001 A.8.15). They do **not** make an organization compliant, and whether they satisfy a given control is for your auditor and security team to decide.

## Hardening checklist for production use

- [ ] Deploy hooks and settings through **managed settings** so they cannot be overridden locally.
- [ ] Set `disableBypassPermissionsMode` in managed settings.
- [ ] Run Claude Code in a sandboxed environment with no production credentials.
- [ ] Ship audit logs off-host to write-once storage; alert on `deny` events.
- [ ] Add your organization's token formats to `secret-patterns.txt`.
- [ ] Review which MCP servers are enabled; hook any that can write.
- [ ] Re-run `tests/run.sh` after every change to the hooks, and review hook changes like production code.
