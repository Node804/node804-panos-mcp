# Playbook: connectivity troubleshooting

"User/host X can't reach service Y — why?" An orchestrated walk over the live
dataplane. Read-only. Assumes the `panos-engineer` invariants. Command-level detail:
`../troubleshooting-commands.md`; PBF specifics: `../routing-vpn.md`.

Why a playbook (not just the reference): the reference is the toolbox; this is the
order to open the drawers so you isolate the failing stage in the fewest calls
instead of dumping config. Report the **first** stage that fails and stop drilling
past it.

## Everything here is dataplane

All of these tools **reject** on a Panorama — there is no data plane there. Pick the
managed device first and pass `firewall=<name>` on every call
(`mcp__panos__list_firewalls` / `mcp__panos__panorama_get_managed_devices` to find
it). The serial redirect resolves a device by hostname or serial.

## Gather the flow

Get the concrete 5-tuple before testing: source IP, destination IP, protocol,
destination port, and — if policy uses identity — the `source_user`. Guessing the
tuple wastes the match tests.

## Diagnostic order (stop at the first failure)

1. **Target.** `mcp__panos__get_firewall_info` — confirm you're on the right
   firewall (on Panorama, choose the managed device in-path).
2. **Policy.** `mcp__panos__test_security_policy_match` with the 5-tuple (+ zones,
   + `source_user` if relevant). Which rule wins? A deny, or a fall-through to the
   cleanup rule, means policy is the blocker — done. If it's an unexpected *allow*,
   note shadowing. (Identity not matching? See `user-id-audit.md`.)
3. **Translation.** If NAT is in play, `mcp__panos__test_nat_policy_match` — confirm
   the translation, then re-run the security test against the **post-NAT**
   destination/zone (the mismatch trap; see `nat-policy.md`).
4. **Routing.** `mcp__panos__test_routing_fib_lookup` on the destination — right
   next-hop, right VR, not a failed-over backup WAN? **Then check PBF**: a
   policy-based-forwarding rule overrides the FIB, so a "correct" route can still be
   bypassed. Read `mcp__panos__get_pbf_rules` (on Panorama:
   `mcp__panos__panorama_get_pre_rules` / `mcp__panos__panorama_get_post_rules` with
   `rule_type="pbf"`) and check whether a PBF rule matches this flow and sends it
   elsewhere.
5. **Reality.** `mcp__panos__get_session_detail` (or `get_sessions` filtered to the
   src/dst) on a live attempt — ingress/egress interface, applied rule, NAT, state.
   This confirms the theory against what the box actually did.
6. **Underlying state, only if still unexplained.** Interfaces/zones
   (`mcp__panos__get_interfaces`, `mcp__panos__get_zones`), L2/next-hop
   (`mcp__panos__get_arp_table`, `mcp__panos__get_dhcp_leases`), the routing table
   (`mcp__panos__get_routing_table`), tunnels (`mcp__panos__get_ipsec_tunnels` — up
   at IKE but no proxy-ID/route still fails; see `../routing-vpn.md`). Anything
   without a dedicated tool: `mcp__panos__run_show_command` (`<show>` only).

## Common resolutions by failing stage

- **Policy:** shadowing by an earlier rule; missing rule; identity not resolving
  (User-ID); wrong zone in the rule.
- **NAT:** no rule / wrong translation; security evaluated against pre-NAT view.
- **Routing/PBF:** wrong VR; backup-WAN default winning post-failover; a PBF rule
  hijacking the path; asymmetric return.
- **VPN:** tunnel down, or up without a route via `tunnel.N` / proxy-ID mismatch.
- **L2/interface:** interface down, no ARP for the next hop, wrong zone binding.

## Report

Name the **single** failing stage and the evidence (the match-test result or session
detail that proves it), then the fix. Don't paste full config when a match test
already isolated the cause. If every stage passes and traffic still fails, say so and
point outward (upstream device, endpoint, path MTU) rather than forcing a verdict.
Read-only — recommend, don't change.
