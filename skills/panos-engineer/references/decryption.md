# SSL/TLS decryption

## Why it matters for an audit

Threat inspection (AV, anti-spyware, vulnerability, URL, WildFire) is largely
blind to **encrypted** traffic. Without decryption, an "allow with full profiles"
rule still can't see inside TLS. So decryption **coverage** is a first-class
security finding, not a nicety.

## Rule types

- **SSL Forward Proxy** — outbound: the firewall acts as a trusted MITM for
  internal clients reaching external HTTPS, using a trusted forward-trust CA.
- **SSL Inbound Inspection** — inbound: decrypts traffic to an internal server
  whose certificate/key the firewall holds.
- **No-decrypt** rules — explicitly exempt traffic (privacy/compliance, e.g.
  health/finance categories, or apps that break under interception).

## Reading them

- Firewall: `mcp__panos__get_decryption_rules` and
  `mcp__panos__get_decryption_profiles`.
- **Panorama**: `get_decryption_rules` is firewall-scoped and **redirects** — use
  `mcp__panos__panorama_get_pre_rules` / `mcp__panos__panorama_get_post_rules`
  with `rule_type="decryption"`, per device group.

## Coverage analysis

1. Establish the target and enumerate scope (device groups on a Panorama).
2. Pull decryption rules per scope. An **empty** decryption rulebase means
   effectively **no outbound TLS inspection** — call that out plainly; it's a
   common and serious gap the earlier guard bug used to hide.
3. Compare decrypt coverage against the security rulebase: allow rules to
   `outside` on web applications with no corresponding forward-proxy decrypt rule
   = inspected in name only.
4. Review **no-decrypt** exemptions — are they scoped to legitimate
   privacy/compliance categories, or so broad they gut coverage?
5. Check decryption **profiles** for weak settings (allowing expired/untrusted
   certs, unsupported cipher modes, or "allow on failure").

## Report

State outbound and inbound coverage separately, list the scopes/device groups with
**zero** decryption, and flag broad no-decrypt exemptions. This is read-only
analysis — recommend, don't change.
