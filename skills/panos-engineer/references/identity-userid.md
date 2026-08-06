# Identity & User-ID

User-ID maps IP addresses to usernames and users to groups so security rules can
match on **user** and **group** instead of raw IPs. When it's healthy, user-based
rules work; when it silently breaks, those rules match no one (or match `unknown`)
and either fail closed (legit users blocked) or fail open (rule skipped, traffic
falls through to a broader rule).

## The three moving parts

1. **IP-to-user mappings** — the live table the dataplane consults. Sourced from
   agents, GlobalProtect, syslog, captive portal, XFF, etc. Read with
   `mcp__panos__get_userid_mappings` (fields: `ip`, `user`, `type`, `vsys`,
   `idle-timeout`, `max-timeout`). **Runtime/dataplane** — this **rejects** on a
   Panorama; target a firewall via `firewall=<name>`.
2. **Group mappings** — the user→group membership pulled from LDAP/AD, used when a
   rule matches a group. Read with `mcp__panos__get_userid_groups` (`name`,
   `members`). Also **runtime** — **rejects** on a Panorama.
3. **User-ID agent config** — how the firewall learns mappings (agent hosts, ports,
   enabled state, LDAP proxy). Read with `mcp__panos__get_userid_config`. This is
   *config*, and it's **template-aware**: on a firewall it reads vsys1; on a
   Panorama it walks every **template**, tagging each entry with its source
   `template` and listing any that `timed_out`.

## Panorama reality

Config lives in templates (`get_userid_config` works, tagged by template). The
**live mapping and group tables do not exist on Panorama** — they're per-firewall
dataplane state. So on a Panorama: read the agent config centrally, then verify
actual mappings/groups **on each firewall** with `firewall=<name>`. Never conclude
"User-ID isn't working" from a Panorama reject — that's expected.

## What "healthy" looks like

- Agent config present and `enabled`, pointing at reachable collectors/LDAP.
- A non-trivial mapping count relative to active users; `type` values consistent
  with the intended sources.
- Group mappings populated with real members (empty groups referenced by policy are
  a red flag).
- Mappings not universally at `max-timeout` with no refresh (suggests the source
  stopped feeding).

## Why rules break

- **No mapping for an IP** → traffic is `unknown`; a user/group rule won't match and
  evaluation falls through. Cross-check with `mcp__panos__test_security_policy_match`
  using a `source_user` to see which rule actually wins.
- **Empty group mapping** → a group-based allow rule matches nobody; users are
  denied by a later rule or the default.
- **Stale agent** (disabled / unreachable in `get_userid_config`) → the whole
  mapping table ages out.
