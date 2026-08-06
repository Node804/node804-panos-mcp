# Playbook: access & admin review

Review administrative access for least-privilege and authentication hygiene.
Read-only. Assumes the `panos-engineer` invariants.

Scope note: cover **both** the firewall/Panorama local admins and, on a Panorama,
the Panorama-level admin roles. Panorama admins often have reach across the whole
managed fleet, so over-privilege there is higher-impact.

## Steps

1. **Admin accounts.** `mcp__panos__get_admins` — enumerate administrators, their
   type (local / RADIUS / TACACS+ / SAML), and assigned role.
2. **Roles.** `mcp__panos__get_admin_roles` (and, on a Panorama,
   `mcp__panos__panorama_get_admin_roles`) — what each custom role actually grants;
   identify superuser / device-admin equivalents.
3. **Authentication.** `mcp__panos__get_auth_profiles` — which auth profiles /
   MFA / auth sequences exist, and whether admins are bound to them vs local
   password only.

## Analyze & flag

- **Superuser sprawl** — more full-access admins than necessary; superuser where a
  scoped custom role would do.
- **Local accounts** — local (non-federated) admins that bypass central identity /
  MFA, especially with high privilege.
- **Weak/absent auth** — admins on local password with no auth profile / MFA;
  auth profiles allowing weak methods.
- **Unused / stale** admins — accounts that should be removed (correlate with
  `mcp__panos__get_config_logs` / `mcp__panos__get_system_logs` for last activity
  where possible).
- **Role drift** — custom roles that have accreted broad permissions.

## Report

Lead with a verdict (e.g. "5 admins, 3 superuser, 2 local-only without MFA"). Then
a table: admin, type (local/federated), role, auth binding (MFA?), concern. Call
out Panorama-level over-privilege separately given its fleet-wide blast radius.
Close with least-privilege recommendations. Read-only — never modify accounts,
roles, or auth config.
