# Routing & VPN

## Config vs runtime (and where it lives on Panorama)

- **Static routes** are *config*: `mcp__panos__get_static_routes`. On a Panorama
  they live in **templates**, so the reader walks every template and tags each
  route with `template`. A named virtual router that doesn't exist in a template
  contributes nothing (not an error).
- **The routing table / FIB** is *runtime/dataplane*: `mcp__panos__get_routing_table`.
  On a Panorama this is **rejected** (no data plane) — run it against a managed
  device via `firewall=<name>`.

## Virtual routers

Routes belong to a virtual router (default name `default`). A firewall can have
multiple VRs with separate route tables; inter-VR traffic needs explicit routes.
When auditing, confirm which VR an interface/zone belongs to before reasoning
about reachability.

## Which route wins

Use `mcp__panos__test_routing_fib_lookup` (dataplane, per firewall) to see the
selected next-hop/interface for a destination. Route selection is
longest-prefix-match, then administrative distance/metric. A default route with a
lower metric on a backup WAN can silently win if the primary is down.

## Policy-based forwarding (overrides the FIB)

A PBF rule can send matching traffic to a next-hop/egress that the routing table
would **not** choose — so "the route is correct" doesn't prove the path. When a flow
takes an unexpected egress, check PBF before blaming routing.

- `mcp__panos__get_pbf_rules` — the PBF rulebase (firewall-scoped). On a Panorama it
  **redirects**: read per device group via `mcp__panos__panorama_get_pre_rules` /
  `mcp__panos__panorama_get_post_rules` with `rule_type="pbf"`.
- PBF is first-match on the *ingress* zone/source/service. A matching rule forwards
  to its configured egress (often a specific tunnel or WAN), bypassing the FIB;
  monitor/disabled state and a failed next-hop (with no fallback) both change the
  outcome. Confirm the effective egress with `mcp__panos__test_routing_fib_lookup`
  plus `mcp__panos__get_session_detail` on a live flow.

## IPSec VPN

- `mcp__panos__get_ipsec_tunnels` — tunnel/SA state (dataplane; per firewall on a
  Panorama). A tunnel that is "up" at IKE but has no matching **proxy-IDs** or a
  missing route still won't pass traffic — check the static route pointing at the
  tunnel interface (`tunnel.N`) and the security policy for the VPN zone.
- Traffic over a tunnel needs: phase-1/2 up **and** a route to the remote subnet
  via the tunnel interface **and** a security rule permitting it.

## GlobalProtect

- `mcp__panos__get_globalprotect_config` (portal/gateway config) and
  `mcp__panos__get_globalprotect_users` (connected users; dataplane, per firewall).
- Tunnel interfaces land in a zone (often `VPNUsers`); security rules must
  reference that zone for GP clients to reach internal resources.

## Common "not routing" causes

- Route exists in a *different* VR than the ingress interface.
- Backup-WAN default route winning due to metric after a failover.
- Static route present in the Panorama template but the device is out of sync
  (`mcp__panos__panorama_get_push_status`).
- Tunnel up but no route via `tunnel.N`, or proxy-ID mismatch.
- A PBF rule silently forwarding the flow to a different egress than the FIB.
