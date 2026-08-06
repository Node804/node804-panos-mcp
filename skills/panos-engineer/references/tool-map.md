# Tool map — which `panos` tool for which job

The server wraps pan-os-python; you drive it through MCP tools, not by writing
pan-os-python code. Firewall-scoped tools read the *local* device; `panorama_*`
tools read Panorama/device-group/template scope. On a Panorama the firewall-scoped
tools guard (redirect or reject) — use the sibling in the right-hand column.

## Target & inventory

| Job | Tool |
|-----|------|
| Identify target (firewall vs Panorama), version, serial | `mcp__panos__get_firewall_info` |
| List configured + managed targets | `mcp__panos__list_firewalls` |
| Panorama-managed fleet + connection status | `mcp__panos__panorama_get_managed_devices` |
| Fleet software/content versions | `mcp__panos__panorama_get_managed_device_software` |
| Server posture / RBAC mode | `mcp__panos__server_status` |

## Security policy (firewall → Panorama)

| Job | Firewall | Panorama |
|-----|----------|----------|
| One-shot audit snapshot | `mcp__panos__summarize_security_policy` | `mcp__panos__panorama_summarize_security_policy` (per device_group) |
| Full rules | `mcp__panos__get_security_rules` | `mcp__panos__panorama_get_pre_rules` / `mcp__panos__panorama_get_post_rules` |
| Count by action | `mcp__panos__count_rules_by_action` | `mcp__panos__panorama_count_rules_per_device_group` |
| Find a named rule | `mcp__panos__find_rule_by_name` | (walk pre/post) |
| All rules, every DG | — | `mcp__panos__panorama_walk_all_rules` |
| Hit counts (dataplane) | `mcp__panos__get_rule_hit_counts` | per device via `firewall=` |
| Unused rules (dataplane) | `mcp__panos__unused_rules` | per device via `firewall=` |

## Profiles, objects, NAT, decryption

| Job | Tool |
|-----|------|
| Security profiles / groups | `mcp__panos__get_security_profiles`, `mcp__panos__get_security_profile_groups` (Panorama shared: `mcp__panos__panorama_get_shared_security_profiles`, `mcp__panos__panorama_get_shared_profile_groups`) |
| Address / service objects & groups | `mcp__panos__get_address_objects`, `mcp__panos__get_address_groups`, `mcp__panos__get_service_objects`, `mcp__panos__get_service_groups` (scope-aware on Panorama) |
| Object inventory counts | `mcp__panos__count_objects_by_type` |
| NAT rules | `mcp__panos__get_nat_rules` (Panorama DG: `mcp__panos__panorama_get_device_group_nat_rules`) |
| Decryption rules / profiles | `mcp__panos__get_decryption_rules`, `mcp__panos__get_decryption_profiles` |

## Network, routing, VPN (firewall-local / template on Panorama)

| Job | Tool |
|-----|------|
| Interfaces / zones / VLANs | `mcp__panos__get_interfaces`, `mcp__panos__get_zones`, `mcp__panos__get_vlans` |
| Routing table (dataplane) / static routes (config) | `mcp__panos__get_routing_table`, `mcp__panos__get_static_routes` |
| IPSec tunnels / GlobalProtect | `mcp__panos__get_ipsec_tunnels`, `mcp__panos__get_globalprotect_config`, `mcp__panos__get_globalprotect_users` |

## Troubleshooting (dataplane — per firewall)

| Job | Tool |
|-----|------|
| Will a flow be allowed? | `mcp__panos__test_security_policy_match` |
| How is a flow NATed? | `mcp__panos__test_nat_policy_match` |
| Which route wins? | `mcp__panos__test_routing_fib_lookup` |
| Live sessions | `mcp__panos__get_sessions`, `mcp__panos__get_session_detail`, `mcp__panos__get_active_sessions` |
| Arbitrary read-only show | `mcp__panos__run_show_command` |

## Logs & change state

| Job | Tool |
|-----|------|
| Traffic / threat / URL / system logs | `mcp__panos__get_traffic_logs`, `mcp__panos__get_threat_logs`, `mcp__panos__get_url_filter_logs`, `mcp__panos__get_system_logs` |
| Uncommitted changes / config diff / config log | `mcp__panos__get_pending_changes`, `mcp__panos__get_config_diff`, `mcp__panos__get_config_logs` |
| Panorama commit / push status | `mcp__panos__panorama_get_commit_status`, `mcp__panos__panorama_get_push_status` |

## Guard cheat-sheet

- **Redirect** (config, on Panorama): the error names the `panorama_*` tool — use it, per device group.
- **Reject** (dataplane, on Panorama): target a managed firewall with `firewall=<name>`.
- `get_system_resources` is *not* guarded — it works on Panorama too.
