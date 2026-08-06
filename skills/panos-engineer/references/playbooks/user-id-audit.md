# Playbook: User-ID / identity audit

Determine whether User-ID is configured and actually working, and whether the
policy's user/group rules can match anyone. Read-only. Assumes the `panos-engineer`
invariants. Background: `../identity-userid.md`.

Why it matters: user-based rules are only as good as the mapping and group tables
behind them. When those go stale, the rules quietly match `unknown` and traffic
falls through to broader rules — a security gap that no rulebase read reveals.

## Firewall path

1. `mcp__panos__get_userid_config` — is a User-ID agent configured and `enabled`,
   pointing at reachable collectors/LDAP?
2. `mcp__panos__get_userid_mappings` — is the live IP-to-user table populated?
   Check volume, `type` distribution, and whether entries are refreshing (not all
   pinned at `max-timeout`).
3. `mcp__panos__get_userid_groups` — are group mappings populated with real
   `members`? An empty group referenced by a rule matches nobody.
4. Correlate with policy: from the security audit, which rules match on **user** or
   **group**? For a representative flow, `mcp__panos__test_security_policy_match`
   with `source_user=<user>` shows which rule actually wins — the direct test that a
   user rule is reachable.

## Panorama path

- `get_userid_config` is **template-aware** and runs on the Panorama: it walks every
  template, tags each entry with `template`, and lists `timed_out` templates. Use it
  for the central "how is User-ID meant to be configured" view.
- `get_userid_mappings` and `get_userid_groups` are **runtime/dataplane** and
  **reject** on a Panorama — the live tables exist only on firewalls. Verify them
  per device with `firewall=<name>` (`mcp__panos__list_firewalls` /
  `mcp__panos__panorama_get_managed_devices`). A reject here is expected, **not**
  "User-ID broken".

## Analysis

- **Configured but not learning:** agent enabled in config, but the mapping table is
  empty or tiny → collector/LDAP unreachable or source misconfigured.
- **Empty / thin group mappings:** groups used by policy with no members → those
  allow rules deny everyone in practice.
- **Stale mappings:** entries all at `max-timeout` with no fresh `type` activity →
  the feeding source likely stopped.
- **Policy dependence:** how much of the rulebase relies on user/group? Heavy
  reliance + weak User-ID health = high blast radius. Light reliance = lower
  priority.
- **`unknown` fallthrough:** user rules that don't match send traffic to later
  rules — check what those are (often a broad allow or the cleanup deny).

## Flag

User-ID enabled but no/stale mappings; empty group mappings referenced by policy;
disabled/unreachable agent; user-based rules whose match can't be demonstrated;
templates that `timed_out` (not assessed).

## Report

State whether User-ID is configured, learning, and mapping groups — as three
separate yes/no/partial verdicts. On a Panorama, separate the central config finding
from per-firewall runtime findings and name any device or template not reached.
Read-only — recommend, don't change.
