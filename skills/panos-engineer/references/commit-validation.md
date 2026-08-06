# Commit & validation

> **Scope note.** This `panos-engineer` skill is **read-only** today. This
> reference explains the candidate/commit model so you can *interpret* change
> state and *preview* diffs — it does **not** authorize making changes. Config
> writes and commits are reserved for a future write-capable revision and require
> a higher RBAC mode on the server.

## Candidate vs running config

PAN-OS edits go to a **candidate** config; nothing takes effect until a
**commit** copies candidate → running. So "the config shows X" (candidate) is not
the same as "the firewall is enforcing X" (running). On Panorama there is a second
step: **commit to Panorama**, then **push** to devices.

## Read-only things you *can* do now

- **See uncommitted changes:** `mcp__panos__get_pending_changes` — what's staged
  but not committed.
- **Preview the diff:** `mcp__panos__get_config_diff` — candidate vs running.
- **Audit who changed what:** `mcp__panos__get_config_logs`.
- **Panorama sync state:** `mcp__panos__panorama_get_commit_status` (last/running
  commit) and `mcp__panos__panorama_get_push_status` (which devices are out of
  sync — i.e., running config lags committed Panorama config).

Use these to answer "is there undeployed config?" and "is the fleet in sync?"
without changing anything.

## The change lifecycle (for the future write-capable revision)

When change playbooks are added, the safe order is:

1. Stage the change (candidate edit).
2. **Validate** the candidate before committing (catches referential/commit
   errors without touching running config).
3. Review the diff (`get_config_diff`) and confirm intent.
4. Commit (firewall) — or commit-to-Panorama then push-to-devices.
5. Verify: re-check `panorama_get_push_status` / relevant runtime state.

The write verbs that perform steps 1/4 (e.g. `commit`, `panorama_commit`,
`panorama_push_to_devices`, and the `add_*`/`set_*`/`delete_*`/`move_*` tools) are
**gated** — blocked in the default `read` mode. A read-only audit never invokes
them; recommend the change and let an operator execute it under the appropriate
mode.
