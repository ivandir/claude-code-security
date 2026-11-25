# Deploying through managed settings

Project-level `.claude/settings.json` is a **default**: anyone with write access to the repo — or the engineer's own local settings — can change it. For regulated environments, deploy the controls through **managed (enterprise) settings**, which take precedence and cannot be overridden by project or user settings.

> **Verify against current documentation.** Managed-settings file locations and supported keys have changed between Claude Code releases. Check the [official settings docs](https://docs.claude.com/en/docs/claude-code/settings) for your version, and test on one machine before rolling out.

## File locations (typical)

| OS | Path |
| --- | --- |
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\ProgramData\ClaudeCode\managed-settings.json` |

Deploy with your MDM or configuration-management tool (Jamf, Intune, Ansible, …). The file and the hook scripts must be **root/admin-owned and not writable by the engineer**.

## Steps

1. Install the hooks somewhere engineers cannot edit, e.g. `/opt/claude-code-security/hooks/` (copy `.claude/hooks/*`, root-owned, mode 755/644). Hooks and `secret-patterns.txt` must live together.
2. Copy [`managed/managed-settings.example.json`](../managed/managed-settings.example.json), set the absolute hook paths, and deploy it to the location above.
3. Set `CLAUDE_AUDIT_DIR` to a path your log shipper watches, e.g. via a shell profile or the managed `env` block.
4. Confirm on a test machine: `/hooks` shows the managed hooks; a write containing a fake token is blocked; a project `settings.json` cannot remove them.
5. Ship logs off-host ([`audit-log-format.md`](audit-log-format.md#shipping-logs-off-host)).

## What the example enforces

- `disableBypassPermissionsMode` — no `--dangerously-skip-permissions`.
- Deny rules for secret locations, outbound network tools and destructive commands.
- The three hooks, from the root-owned install path.
- `allowManagedHooksOnly` — only managed hooks run, so a project cannot swap in a weaker one. *(Confirm this key exists in your Claude Code version; if not, rely on file permissions and review.)*

## Why the hooks protect themselves too

`enforce-boundaries.sh` refuses edits to `.claude/hooks/` and `.claude/settings*.json` in the project. With managed settings the authoritative copies live outside the project entirely, which the boundary hook also blocks by default.
