# Security policy

## Structure of a rule

A security rule matches on: source/destination **zone**, source/destination
**address**, **application** (App-ID), **service** (port), **user** (User-ID),
and **URL category**; then takes an **action** (allow/deny/drop/reset) and,
on allow, applies **profiles** (or a profile group) for threat inspection and
**logging** settings.

## Evaluation order (first match wins)

Rules are evaluated **top-down; the first match wins**. On a Panorama the
effective order is the flattened chain (see `panorama-hierarchy.md`):
shared pre → ancestor/DG pre → local → DG/ancestor post → shared post → defaults.

Consequences to audit for:
- **Shadowing** — a broad rule above a narrower one makes the narrower rule
  unreachable. Confirm on a firewall with `mcp__panos__test_security_policy_match`
  using the shadowed rule's own criteria; if the match resolves to an *earlier*
  rule, it is shadowed.
- **any-any** — source AND destination AND application all `any`. High blast
  radius; almost always worth flagging.

## What to inspect

- Snapshot first: `mcp__panos__summarize_security_policy` (firewall) or
  `mcp__panos__panorama_summarize_security_policy` per device group. It returns
  counts, action breakdown, any-any, logging-off, rules-without-inspection, and
  zones referenced.
- Detail: `mcp__panos__get_security_rules` (firewall) /
  `mcp__panos__panorama_get_pre_rules` + `mcp__panos__panorama_get_post_rules`
  (Panorama). Project with `fields=` to keep it lean.

## Common findings

- **any-any allow** — tighten source/dest/app.
- **Logging off** — both log-start and log-end disabled → no forensic trail.
- **No inspection** — allow rule with no profile group / profile setting; traffic
  is permitted without threat scanning. Confirm the referenced profiles/groups
  actually exist (`mcp__panos__get_security_profiles`,
  `mcp__panos__get_security_profile_groups`, or the shared variants on Panorama).
- **Disabled rules** left in place — intent unclear.
- **Overly broad zones** — untrusted zones on the source of permissive rules.

## Profiles vs profile groups

A rule can attach individual profiles (AV, anti-spyware, vulnerability, URL,
file-blocking, wildfire) or a **profile group** that bundles them. A profile group
that is empty or missing members inspects nothing — treat it as "no inspection".
