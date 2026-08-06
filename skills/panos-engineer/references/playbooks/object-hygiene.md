# Playbook: object hygiene

Find unused, duplicate, and orphaned address/service objects and tags — the
object-level twin of `policy-hygiene.md` (which covers rules). Read-only. Assumes
the `panos-engineer` invariants.

Why it matters: object sprawl makes policy hard to reason about and hides mistakes —
two objects for the same host, an address group nobody references, a tag applied to
nothing. None of it is dangerous on its own, but it inflates the config an auditor
must trust and often signals drift from a deprovisioned service.

## Read (scope-aware — one call each)

These readers are **scope-aware**: on a firewall they read vsys1; on a Panorama they
read `shared` + every device group and tag each row with `scope` (and list
`timed_out` scopes). No `panorama_*` redirect needed.

1. `mcp__panos__count_objects_by_type` — the inventory snapshot (address by
   ip-netmask/fqdn/range, service by tcp/udp, tag, application) to size the job.
2. `mcp__panos__get_address_objects` and `mcp__panos__get_address_groups`.
3. `mcp__panos__get_service_objects` and `mcp__panos__get_service_groups`.
4. `mcp__panos__get_tags` — tags defined vs. actually applied.
5. `mcp__panos__get_application_filters` — filters referenced by policy or not.

Targeted lookups: `mcp__panos__find_address_object` resolves a name substring **or**
an IP/CIDR to the objects that contain it (scope-tagged) — use it to spot multiple
objects covering the same address. On Panorama you can also read a single scope
explicitly via `mcp__panos__panorama_get_device_group_address_objects` /
`_address_groups` / `_service_objects` / `_service_groups` (and the
`panorama_get_shared_*` variants) when you want one device group, not the whole
walk.

## Determine "used vs unused"

An object is *used* if referenced by a rule (any rulebase), a group, or another
object. Cross-reference against the policy:

- Firewall: `mcp__panos__get_security_rules` (+ NAT/decryption/PBF rulebases) and the
  group memberships above.
- Panorama: walk rules per device group with `mcp__panos__panorama_get_pre_rules` /
  `mcp__panos__panorama_get_post_rules` (or `mcp__panos__panorama_walk_all_rules`),
  and remember **inheritance** — a `shared` object may be referenced only by a
  child device-group rule, so an object isn't unused until it's unreferenced across
  its own scope **and** all descendants (see `../panorama-hierarchy.md`).

## Analysis

- **Unused objects/groups:** defined, referenced by no rule/group/object. Highest-
  confidence in `shared`/vsys1; on Panorama confirm no descendant references before
  claiming unused.
- **Duplicates:** two+ objects with the same value (same IP/CIDR, same
  protocol/port) — surfaced via `find_address_object` on the address, or by grouping
  service objects by port. Consolidation candidates.
- **Empty groups:** address/service groups with no members — match nothing;
  a rule using one is effectively broken.
- **Orphaned tags:** tags defined but applied to no object/rule, or applied only to
  disabled rules.
- **Shadowing scope risk (Panorama):** a `shared` object and a device-group object
  of the **same name** — the more specific wins; flag the collision.

## Flag

Unused objects/groups; duplicate values; empty groups referenced by policy; orphaned
tags; same-name shared/DG object collisions; any scope that `timed_out` (not
assessed, so "unused" claims there are unproven).

## Report

Lead with counts (total objects, % unused, duplicates, empty groups). List
consolidation candidates with their scope. Be explicit that "unused" is only as
sound as the rule walk behind it — on a Panorama, name any device group not read.
Read-only — recommend cleanup, never delete.
