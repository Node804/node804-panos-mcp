# Playbook: audit the security policy

Risk-and-hygiene review of a PAN-OS security policy. Read-only. Assumes the
`panos-engineer` invariants (target detection, guards, scope/`timed_out`,
read-only). Background: `../security-policy.md`, `../panorama-hierarchy.md`.

## Firewall path

1. **Snapshot.** `mcp__panos__summarize_security_policy` — counts, action
   breakdown, any-any, logging-off, rules-without-inspection, zones referenced.
2. **Drill into what the snapshot flagged** (only fetch what you need):
   - Broad rules → `mcp__panos__get_security_rules` with
     `fields=["name","source","destination","application","service","action"]`.
   - Inspection → `mcp__panos__get_security_profile_groups` +
     `mcp__panos__get_security_profiles` (confirm referenced profiles exist and
     aren't empty placeholders).
   - Effectiveness → `mcp__panos__get_rule_hit_counts`, `mcp__panos__unused_rules`.
   - Specific rule → `mcp__panos__find_rule_by_name`.

## Panorama path

1. **Scope.** `mcp__panos__panorama_get_device_groups` +
   `mcp__panos__panorama_get_device_group_hierarchy`; optionally
   `mcp__panos__panorama_count_rules_per_device_group` to target the heavy DGs.
2. **Per device group.** `mcp__panos__panorama_summarize_security_policy` with the
   `device_group` and `include_shared=true`.
3. **Drill in** where flagged: `mcp__panos__panorama_get_pre_rules` /
   `mcp__panos__panorama_get_post_rules` (`rule_type="security"`);
   `mcp__panos__panorama_get_shared_profile_groups` /
   `mcp__panos__panorama_get_shared_security_profiles` for shared posture.
4. Honor `timed_out` — a partial walk is not a clean posture.

## Flag

any-any allow · logging off (start+end) · allow with no inspection · disabled
rules still present · zero-hit/unused allow rules · broad untrusted-zone exposure.

## Report

One-line posture verdict, then findings ranked by risk (rule, scope/DG, issue,
why). On a Panorama group by device group and list `timed_out` scopes as "not
assessed". Close with ordered remediation. No commits.
