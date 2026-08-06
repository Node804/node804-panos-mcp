# Playbook: subscription & content health

Answer "is this firewall actually protected, or only configured to be?" Read-only.
Assumes the `panos-engineer` invariants.

Why it matters: an expired Threat Prevention, URL, or WildFire subscription leaves
the *policy* intact while the *protection* silently lapses — profiles are attached,
logs look normal, and traffic passes uninspected. Stale content (signatures days or
weeks behind) has the same effect for new threats. This is the gap a rule-only audit
misses.

## Firewall path

1. `mcp__panos__get_licenses` — installed licenses with `feature`, `expires`,
   `issued`. This is the ground truth for what's active. (The activation
   `authcode` is omitted by default — do **not** request it; it's a credential.)
2. `mcp__panos__get_antivirus_version` — active AV / threat / WildFire signature
   versions and release dates. Runs `show system info`.
3. `mcp__panos__get_content_versions` — available vs downloaded/current content
   packages (`current`, `downloaded`, `released-on`).
4. `mcp__panos__get_wildfire_status` — WildFire cloud registration/subscription and
   `license-expired`. **Firewall-only** — this one **rejects** on a Panorama (the
   appliance holds no per-firewall WildFire connection); target a managed device
   via `firewall=<name>`.

## Panorama path

- `get_licenses`, `get_antivirus_version`, `get_content_versions` run against the
  **Panorama appliance itself** (its own licenses and content) — useful, but *not*
  the managed fleet's state. To assess a firewall's subscriptions, target it:
  `firewall=<name>` (find one via `mcp__panos__list_firewalls` /
  `mcp__panos__panorama_get_managed_devices`).
- `mcp__panos__panorama_get_managed_device_software` gives per-device software and
  content baselines across the fleet in one call — use it for the fleet-wide
  "who's behind" view, then drill into a lagging device.
- `get_wildfire_status` **rejects** on Panorama; only meaningful per firewall.

## Analysis

- **Expired / expiring licenses:** any `feature` past `expires`, or within ~30 days
  of it. Threat Prevention, URL Filtering, WildFire, DNS Security, and GlobalProtect
  are the protection-relevant ones. Rank an *expired* Threat/URL/WildFire license as
  a top finding — it means active blind spots.
- **Stale content:** AV/threat/WildFire signature release dates lagging the current
  available package (`get_content_versions` with `current=false` but a newer
  `released-on`). A device with dynamic updates disabled drifts here.
- **Config vs. protection mismatch:** a security policy with full profile groups
  (from `audit-security-policy`) but a lapsed Threat license — flag the pairing
  explicitly; each looks fine alone.
- **Fleet drift (Panorama):** managed devices on inconsistent content versions —
  the laggards are the exposed ones.

## Flag

Expired or soon-to-expire protection licenses; content signatures materially behind
current; WildFire not registered/subscribed; fleet members lagging the content
baseline.

## Report

Lead with a protection verdict (protected / partially / lapsed), then a per-feature
license table with days-to-expiry, then content currency, then any config-vs-license
mismatch. On a Panorama, state clearly whether you assessed the appliance or the
managed devices, and name any device not reached. Read-only — recommend renewal /
content update, never perform it.
