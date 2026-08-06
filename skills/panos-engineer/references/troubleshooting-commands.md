# Live troubleshooting

For "why is this traffic blocked / not routing / not tunneling" questions. All of
these are **dataplane** — on a Panorama they are rejected; run them against a
managed device via `firewall=<name>` (serial redirect resolves managed devices by
hostname or serial).

## The three match tests (use these before reading raw config)

| Question | Tool | Notes |
|----------|------|-------|
| Will this flow be permitted, and by which rule? | `mcp__panos__test_security_policy_match` | Give the 5-tuple + zones; returns the matching rule. Points at the *actual* first-match rule — the fast way to find shadowing or the wrong permit. |
| How is this flow translated? | `mcp__panos__test_nat_policy_match` | Returns the NAT rule + translated addresses. Compare pre/post-NAT with the security result (see `nat-policy.md`). |
| Which route/next-hop wins? | `mcp__panos__test_routing_fib_lookup` | Longest-prefix then metric; catches backup-WAN and wrong-VR cases. |

## Sessions

- `mcp__panos__get_active_sessions` / `mcp__panos__get_sessions` — is the flow even
  establishing? Filter to the src/dst of interest.
- `mcp__panos__get_session_detail` — per-session state, ingress/egress interface,
  applied rule, NAT — confirms what the firewall actually did with a live flow.

## Supporting state

- Interfaces/zones: `mcp__panos__get_interfaces`, `mcp__panos__get_zones`.
- ARP / DHCP: `mcp__panos__get_arp_table`, `mcp__panos__get_dhcp_leases`.
- Routing table: `mcp__panos__get_routing_table`.
- Anything without a dedicated tool: `mcp__panos__run_show_command` (read-only
  `<show>` commands only).

## A reliable diagnostic order

1. `get_firewall_info` — confirm target; on Panorama pick the managed device.
2. `test_security_policy_match` — is policy the blocker, and which rule?
3. If NAT is involved, `test_nat_policy_match` — verify translation and re-check
   security against the post-NAT view.
4. `test_routing_fib_lookup` — is egress routing correct (right VR, right WAN)?
5. `get_session_detail` on a live flow to confirm the theory against reality.
6. Only then read the raw rulebase/routes for the specific object in question.

Report the first stage that fails and why; don't dump full config when a match
test already isolated the cause.
