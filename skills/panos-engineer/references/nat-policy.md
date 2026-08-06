# NAT policy

## The key mental model: NAT is evaluated on the *original* packet, security on the *post-NAT* zone

NAT rules match the **original** (pre-translation) packet — original source/dest
zone, address, and service. But the **destination zone** in a NAT rule is derived
from a route lookup on the *original* destination, and the **security** policy is
then evaluated using the **post-NAT** (translated) destination but the
**pre-NAT** zones for source/dest as computed. This mismatch is the usual cause of
"NAT looks right but traffic is still blocked": the security rule must be written
for the zone the translated packet lands in.

## Rule types

- **Source NAT** — typically outbound; hides internal addresses behind an
  interface/pool (dynamic-ip-and-port is the common case).
- **Destination NAT** — inbound; publishes an internal service on a public IP
  (port-forward / static). Often paired with a security rule whose destination is
  the **original (public)** address but destination zone is the **internal** zone.
- **U-Turn / hairpin NAT** — internal client reaching an internal service via its
  public IP; a frequent misconfiguration.

## Order

NAT rules are top-down, first match wins, same flattening as security on a
Panorama (pre/post per device group). Read them with `mcp__panos__get_nat_rules`
(firewall) or `mcp__panos__panorama_get_device_group_nat_rules` (Panorama DG).

## Troubleshooting a NAT flow

Use `mcp__panos__test_nat_policy_match` on the firewall with the flow's original
5-tuple to see which NAT rule matches and the resulting translation. Then check
security with `mcp__panos__test_security_policy_match` using the post-NAT
destination. If NAT matches but security denies, the security rule's zones/address
are almost always written against the wrong (pre- vs post-NAT) view.

On a Panorama, both `test_*` tools are dataplane — run them against a managed
device via `firewall=<name>`, not against Panorama.
