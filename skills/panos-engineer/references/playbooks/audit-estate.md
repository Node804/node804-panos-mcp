# Playbook: Panorama estate overview

Health-and-inventory snapshot of a Panorama-managed estate. **Panorama only** —
if `mcp__panos__get_firewall_info` shows a firewall, this doesn't apply (suggest
`audit-security-policy.md`). Read-only. Background: `../panorama-hierarchy.md`.

## 1. Panorama itself
- `mcp__panos__get_firewall_info` — model, version, uptime, serial.
- `mcp__panos__panorama_get_ha_status` — is the Panorama HA pair healthy/in-sync?

## 2. Managed fleet
- `mcp__panos__panorama_get_managed_devices` — every device + `connected` status.
- `mcp__panos__panorama_get_managed_device_software` — sw/content version skew.
- `mcp__panos__list_firewalls` — cross-check serial-reachable inventory.

**Flag:** disconnected devices; PAN-OS version drift; stale content/threat/AV
(devices well behind the fleet, or `0` signature versions).

## 3. Configuration structure
- `mcp__panos__panorama_get_device_groups` +
  `mcp__panos__panorama_get_device_group_hierarchy`.
- `mcp__panos__panorama_count_rules_per_device_group` (watch its `timed_out`).
- `mcp__panos__panorama_get_templates` + `mcp__panos__panorama_get_template_stacks`.

**Flag:** device groups with zero rules; templates/stacks bound to no device;
unexpectedly deep/flat hierarchy.

## 4. Commit & push sync
- `mcp__panos__get_pending_changes` — uncommitted Panorama changes.
- `mcp__panos__panorama_get_commit_status` — last/running Panorama commit.
- `mcp__panos__panorama_get_push_status` — devices out of sync (pending/failed).

**Flag:** uncommitted changes; failed pushes; devices whose running config lags
committed Panorama config (policy you think is deployed but isn't).

## 5. Logging infra (optional)
- `mcp__panos__panorama_get_log_collectors` +
  `mcp__panos__panorama_get_collector_groups` — flag disconnected collectors.

## Report
One-line fleet-health verdict; then a device table (device, model, sw, content,
connected, in-sync), structure summary (DGs/hierarchy/rules-per-DG, templates),
sync issues, ordered remediation. Surface every `timed_out` scope as "not
assessed". Read-only — never commit or push.
