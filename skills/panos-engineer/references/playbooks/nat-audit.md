# Playbook: NAT policy audit

Review the NAT rulebase for risk, overlap, and correctness — the NAT counterpart to
`audit-security-policy.md`. Read-only. Assumes the `panos-engineer` invariants.
Background: `../nat-policy.md`.

Why it matters: NAT bugs are quiet. A too-broad source NAT can expose internal hosts
behind the wrong public IP; an overlapping destination NAT can hijack a published
service; a NAT rule with no matching security rule (evaluated on the *post-NAT* zone)
means traffic that translates but never passes — or vice versa. NAT and security are
audited together or not at all.

## Firewall path

1. `mcp__panos__get_nat_rules` — the local NAT rulebase (source/destination/
   bidirectional). Read order top-to-bottom; NAT is first-match like security.
2. For any rule in question, `mcp__panos__test_nat_policy_match` shows which NAT rule
   a specific flow hits and the resulting translation — the ground truth for
   overlap/precedence questions.

## Panorama path

`get_nat_rules` is firewall-scoped and **redirects** on a Panorama. Instead:

1. Enumerate device groups (`mcp__panos__panorama_get_device_groups` +
   `mcp__panos__panorama_get_device_group_hierarchy`).
2. Per device group, read NAT rules via
   `mcp__panos__panorama_get_device_group_nat_rules`, or via
   `mcp__panos__panorama_get_pre_rules` / `mcp__panos__panorama_get_post_rules` with
   `rule_type="nat"` when you need the pre/post split.
3. Honor `timed_out` — a device group that didn't return is **not assessed**.

## Analysis

- **Post-NAT security mismatch:** the classic trap. Security policy matches the
  **post-NAT destination and zone** but the **pre-NAT** source. Cross-check each
  destination-NAT rule against the security policy
  (`mcp__panos__test_security_policy_match` on the translated address/zone) — a
  published service that NATs but has no permitting security rule is broken; one
  that's reachable from `any` is exposed. See `../nat-policy.md`.
- **Overlap / shadowing:** an earlier broad NAT rule swallowing a later specific one
  — confirm with `test_nat_policy_match` on a flow the specific rule was meant to
  catch.
- **Over-broad source NAT:** `source=any` / large zones hiding behind a single IP
  where a scoped rule was intended.
- **Bidirectional NAT reach:** a `bi-directional` source NAT auto-creates an inbound
  destination NAT — verify that inbound exposure is intended.
- **Dead rules:** disabled NAT rules, or rules whose zones/interfaces no longer
  exist.

## Flag

Destination NAT with no matching security rule (or reachable from `any`); overlapping
/ shadowed NAT rules; over-broad source NAT; unintended bidirectional exposure;
disabled or orphaned rules; any `timed_out` scope.

## Report

Lead with a verdict on NAT correctness and exposure. List destination-NAT services
and whether each has a corresponding security rule; flag overlaps with the flow that
proves them. On a Panorama, report per device group and mark any not assessed.
Read-only — recommend, don't change.
