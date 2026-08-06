# Panorama hierarchy & scope model

Panorama centrally manages firewalls through two parallel trees. Getting the scope
model right is what separates a correct audit from an empty one.

## The two trees

- **Device groups (policy & objects).** Security/NAT/decryption rules and objects
  (addresses, services, profiles). Hierarchical: a device group can have a parent,
  and a firewall inherits its whole ancestor chain plus **shared**.
- **Templates & template stacks (network & device config).** Interfaces, zones,
  virtual routers, VLANs, IPSec, GlobalProtect, DNS proxy, User-ID. A firewall
  binds to a **template stack** (an ordered set of templates). Network/device
  config does **not** live in device groups.

Plus **shared** — the top of the object/policy tree, visible to every device group.

## How rules flatten onto a firewall

For any rulebase (security, NAT, decryption), the effective order a firewall
evaluates is:

```
shared pre-rules
  → ancestor DG pre-rules (top-down)
    → device-group pre-rules
      → firewall-local rules (rare when Panorama-managed)
    → device-group post-rules
  → ancestor DG post-rules
→ shared post-rules
→ default rules
```

So **pre-rules** sit above local rules and **post-rules** below them. A permissive
shared/ancestor pre-rule can shadow everything beneath it — always consider the
full inherited chain, not one device group in isolation.

- Get the tree: `mcp__panos__panorama_get_device_groups` +
  `mcp__panos__panorama_get_device_group_hierarchy` (parent→child).
- Per-DG rules: `mcp__panos__panorama_get_pre_rules` /
  `mcp__panos__panorama_get_post_rules` (`rule_type` = security/nat/decryption).
- Combined per-DG audit incl. shared: `mcp__panos__panorama_summarize_security_policy`
  with `include_shared=true`.

## Scope tags & empty shared

Scope-aware object/profile readers walk **shared + every device group** and tag
each row with `scope`. Template-aware readers walk **every template** and tag with
`template`.

- An empty `shared` scope is **normal** — many estates keep the working config in
  a device group (e.g. a catch-all "Internet-FWs" DG), not in shared.
- Always inspect the `timed_out` field. A device group or template that timed out
  is **not assessed** — never fold it into an "empty / clean" conclusion.

## Objects resolve by scope, too

An address/service/profile referenced by a rule may be defined in the same device
group, an ancestor, or shared. When a rule references a name you can't find in the
DG, check ancestors and shared (`mcp__panos__panorama_get_shared_address_objects`,
`mcp__panos__panorama_get_shared_service_objects`, etc.) before calling it broken.

## Sync reality

Panorama config is the *intended* state. What a firewall enforces is its last
**pushed** running config. Check `mcp__panos__panorama_get_push_status` — a device
out of sync is running policy that differs from what Panorama shows.
