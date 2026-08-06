# Playbook: change & drift review

Answer "what has changed, who changed it, and is it actually deployed?" Read-only
— preview and diff only. Assumes the `panos-engineer` invariants. Background:
`../commit-validation.md`.

Key idea (see `../commit-validation.md`): edits go to a **candidate** config;
nothing is enforced until a **commit** (and on Panorama, a **push** to devices).
So "the config shows X" ≠ "the firewall enforces X".

## Steps

1. **Uncommitted work.** `mcp__panos__get_pending_changes` — is there staged config
   not yet committed? Who/what is dirty.
2. **Preview the diff.** `mcp__panos__get_config_diff` — candidate vs running; the
   concrete pending delta.
3. **Audit history.** `mcp__panos__get_config_logs` — who changed what, when
   (admin, action, target). Surface recent or unexpected changes.
4. **Panorama sync (if Panorama).**
   - `mcp__panos__panorama_get_commit_status` — state of the last/running Panorama
     commit.
   - `mcp__panos__panorama_get_push_status` — which managed devices are out of sync
     (pending/failed pushes). An out-of-sync device runs policy that differs from
     what Panorama shows — the highest-value drift finding.

## Flag

- Uncommitted candidate changes (undeployed intent).
- Devices out of sync with committed Panorama config (drift between intended and
  enforced policy).
- Failed pushes / failed or stuck commits.
- Unexpected or unattributed recent config-log entries.

## Report

Lead with deployment state ("2 devices out of sync; 1 uncommitted change on
Panorama"). Then: pending changes + diff summary, recent change-log entries
(who/what/when), and per-device sync status. Distinguish **intended** (candidate/
committed on Panorama) from **enforced** (device running config). Read-only —
recommend commit/push actions for an operator to run under the appropriate mode;
never execute them.
