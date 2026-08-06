# Playbook: log review & threat hunt

Triage a firewall/Panorama's logs for what matters. Read-only. Assumes the
`panos-engineer` invariants (target detection, guards, `timed_out`, read-only).

## Where logs live

Firewall logs are local. On a **Panorama**, the log tools read Panorama's
**aggregated** log database (managed-device logs forwarded to Panorama / its log
collectors) — so a Panorama query spans the fleet. To scope to one device, add a
device filter or query that device directly via `firewall=<name>`. Log volume is
large: always constrain with time window, filters, and `pagination`, and prefer a
narrow query over a broad dump.

## Steps

1. **Target & currency.** `mcp__panos__get_firewall_info` for the target;
   `mcp__panos__get_content_versions` to confirm threat/AV/WildFire signatures are
   current (stale content = blind spots that skew a "no threats" read).
2. **Threats by severity.** `mcp__panos__get_threat_logs` — group by severity;
   surface critical/high first, then repeat offenders (same threat ID or
   source/destination).
3. **Denied bursts / blocked traffic.** `mcp__panos__get_traffic_logs` filtered to
   `action=deny` (or drop/reset) — look for spikes, scans (one source → many
   dst/ports), and top talkers (by session count / bytes).
4. **URL activity.** `mcp__panos__get_url_filter_logs` — blocked categories,
   high-risk category hits, and unusual destinations.
5. **System health signals.** `mcp__panos__get_system_logs` — HA transitions,
   commit/push events, link flaps, resource warnings that correlate with the above.

## Flag

- Top talkers (by sessions/bytes) worth investigating.
- Denied bursts / scan patterns (one source, many targets or ports).
- Threats by severity — especially critical/high and repeat offenders.
- URL hits in high-risk or should-be-blocked categories.
- Stale content versions undermining detection.

## Report

Lead with the headline (e.g. "3 critical threats, one host generating 60% of
denies"). Then sections: top threats (severity, name, source→dest, count), denied
traffic patterns / top talkers, notable URL activity, and any correlated system
events. State the time window and scope (fleet-wide vs a device). Note anything
`timed_out` or truncated by pagination. Recommend next steps; never change config.
