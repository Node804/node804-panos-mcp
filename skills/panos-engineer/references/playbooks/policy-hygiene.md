# Playbook: policy hygiene & cleanup

Find cleanup/optimization gaps — unused, zero-hit, shadowed, overly broad,
redundant, and disabled rules. Read-only. This is the **hygiene** lens; the risk
lens is `audit-security-policy.md`. Background: `../security-policy.md`.

## Two kinds of gap — read from different places

- **Rulebase hygiene** (shadowed, broad, redundant, disabled) is a property of the
  ordered rule set — read from the rulebase (firewall-local, or Panorama pre/post
  per device group).
- **Usage hygiene** (unused, zero-hit) is **dataplane** — hit counters live on the
  firewall. `mcp__panos__unused_rules` and `mcp__panos__get_rule_hit_counts` are
  therefore **rejected** on a Panorama; run them **per managed device** via
  `firewall=<device>`.

## Firewall path
1. `mcp__panos__summarize_security_policy` — frames the cleanup surface.
2. Usage: `mcp__panos__unused_rules`, `mcp__panos__get_rule_hit_counts` (zero-hit
   allow rules). *A newly created rule with 0 hits isn't necessarily stale* —
   weigh last-hit/creation time.
3. Structure: `mcp__panos__get_security_rules`
   (`fields=[...,"disabled"]`) for broad, disabled, duplicate rules.
4. Shadow check: `mcp__panos__test_security_policy_match` with a suspect rule's own
   criteria; if it resolves to an *earlier* rule, the suspect is shadowed.
   `mcp__panos__find_rule_by_name` pulls a specific rule.

## Panorama path
1. Scope: `mcp__panos__panorama_get_device_groups` +
   `mcp__panos__panorama_get_device_group_hierarchy`;
   `mcp__panos__panorama_count_rules_per_device_group`.
2. Rulebase hygiene per DG: `mcp__panos__panorama_get_pre_rules` /
   `mcp__panos__panorama_get_post_rules`. Shadowing across pre→DG→post is
   *approximate* from static order here; confirm on a device.
3. Usage across the estate: enumerate with
   `mcp__panos__panorama_get_managed_devices`, then per **connected** device call
   `mcp__panos__unused_rules` / `mcp__panos__get_rule_hit_counts` with
   `firewall=<device>`. A pushed rule unused on **every** device it lands on is a
   strong cleanup candidate; used on some, it isn't.

## Rank by cleanup confidence
disabled → shadowed (confirmed) → unused on all devices → zero-hit (with new-rule
caution) → redundant/duplicate → overly broad.

## Report
One-line hygiene verdict + candidate count; table ranked by confidence (rule,
scope/DG, gap type, evidence e.g. "0 hits on all 8 devices" / "shadowed by
<rule>"); note `timed_out` scopes. Read-only — propose the cleanup; never commit.
