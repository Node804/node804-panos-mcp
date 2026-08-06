# Playbook: decryption coverage

Assess how much traffic is actually being inspected inside TLS. Read-only. Assumes
the `panos-engineer` invariants. Background: `../decryption.md`.

Why it matters: threat profiles are largely blind to encrypted traffic, so an
"allow with full profiles" rule over HTTPS inspects little without a matching
decryption rule. Coverage is a first-class finding — **an empty decryption
rulebase means effectively no outbound TLS inspection.** (This is the exact case
the earlier Panorama guard bug hid, returning a misleading empty result.)

## Firewall path

1. `mcp__panos__get_decryption_rules` — the local decryption rulebase.
2. `mcp__panos__get_decryption_profiles` — profile strength.

## Panorama path

`get_decryption_rules` is firewall-scoped and **redirects** on a Panorama. Instead:

1. Enumerate device groups (`mcp__panos__panorama_get_device_groups` +
   `mcp__panos__panorama_get_device_group_hierarchy`).
2. Per device group, read decryption rules via
   `mcp__panos__panorama_get_pre_rules` and `mcp__panos__panorama_get_post_rules`
   with `rule_type="decryption"`.
3. Watch `timed_out` — a DG that didn't return is **not assessed**, not "no
   decryption".

## Analysis

- **Zero-decryption scopes:** any firewall/DG with an empty decryption rulebase →
  no outbound TLS inspection. State it plainly.
- **Coverage vs exposure:** cross-check against the security policy — allow rules
  to `outside` on web apps with no corresponding SSL-Forward-Proxy decrypt rule are
  inspected in name only.
- **No-decrypt exemptions:** legitimate (privacy/compliance categories) or so
  broad they gut coverage?
- **Profile weakness:** profiles permitting expired/untrusted certs, unsupported
  cipher modes, or "allow on failure".

## Flag

Undecrypted scope (firewalls/DGs with no decrypt rules); broad no-decrypt
exemptions; weak decryption profiles; inbound servers lacking inbound inspection.

## Report

State outbound and inbound coverage separately; list scopes/device groups with
**zero** decryption; flag broad no-decrypt exemptions and weak profiles; mark any
`timed_out` scope as "not assessed". Read-only — recommend, don't change.
