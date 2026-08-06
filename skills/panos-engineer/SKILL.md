---
name: panos-engineer
description: >-
  Work with Palo Alto Networks PAN-OS firewalls and Panorama through the panos MCP
  server — audit security / NAT / decryption policy, review a Panorama-managed
  estate, troubleshoot connectivity, routing, and VPN, and inspect logs. Read-only
  analysis and auditing (never commits). Use for any PAN-OS or Panorama question:
  policy review, rule cleanup, fleet health, "why is traffic blocked", decryption
  coverage, log triage.
license: Apache-2.0
metadata:
  domain: cybersecurity
  subdomain: network-security
  read_only: true
---

# PAN-OS engineer

Drive the `panos` MCP server to analyze and troubleshoot Palo Alto firewalls and
Panorama. This skill is **read-only** — it audits, inspects, and explains; it
never changes config or commits. (Config-change playbooks are reserved for a
future write-capable revision; see `references/commit-validation.md`.)

## Always do this first — invariants

The `panos` server also states these in its own instructions; they are the
difference between a correct answer and a confidently-wrong empty one.

1. **Determine the target.** Call `mcp__panos__get_firewall_info`. A `model` of
   `Panorama` or `M-*` is a **Panorama**; anything else is a **firewall**.
   Behavior differs sharply — branch on it.
2. **On a Panorama, follow the guards.** Firewall-scoped config tools return a
   **redirect** error naming the correct `panorama_*` sibling (re-issue per device
   group); dataplane/runtime tools return a **reject** error (target a managed
   device via `firewall=<name>`). **Never** read a guard error as "nothing
   configured".
3. **Honor scope/template tags and `timed_out`.** An empty `shared` scope is
   normal — real config lives in device groups and templates. A walk that reports
   `timed_out` scopes is partial, not empty; say so.
4. **Read-only.** Never instruct a commit, push, or config write.
5. **Spend tokens well.** Prefer summary/count tools before full dumps; narrow
   list reads with `pattern=`, `fields=`, and `pagination`.

If you are unsure which tool maps to a task, read `references/tool-map.md`.

## Choose the reference for the task

Read only what the task needs (each reference is loaded on demand):

| The task is about… | Read |
|--------------------|------|
| Panorama structure: shared vs device group vs template, rule flattening | `references/panorama-hierarchy.md` |
| Security rules: structure, evaluation order, profiles, shadowing | `references/security-policy.md` |
| NAT rules: source/dest NAT, pre/post-NAT zones, match testing | `references/nat-policy.md` |
| Routing / VPN: virtual routers, routes, FIB, PBF, IPSec, GlobalProtect | `references/routing-vpn.md` |
| Identity: User-ID mappings, group mappings, agent config; why user rules miss | `references/identity-userid.md` |
| SSL decryption: forward-proxy vs inbound, coverage gaps | `references/decryption.md` |
| "Why is traffic blocked / not routing" live troubleshooting | `references/troubleshooting-commands.md` |
| Change/commit/validation concepts (read-only preview today) | `references/commit-validation.md` |
| Which MCP tool does what; firewall↔panorama tool pairs | `references/tool-map.md` |

## Predefined audit playbooks

For the common named jobs, follow the matching playbook end to end:

| Ask | Playbook |
|-----|----------|
| "Review / audit the security policy for risk" | `references/playbooks/audit-security-policy.md` |
| "Review / audit the NAT policy for risk & overlap" | `references/playbooks/nat-audit.md` |
| "Find unused / shadowed / dead rules; clean up policy" | `references/playbooks/policy-hygiene.md` |
| "Find unused / duplicate / orphaned objects & tags" | `references/playbooks/object-hygiene.md` |
| "Review logs / hunt threats; top talkers, denied bursts" | `references/playbooks/log-review.md` |
| "Is TLS traffic being decrypted / inspected?" | `references/playbooks/decryption-coverage.md` |
| "Are subscriptions active and content current? (protected or just configured?)" | `references/playbooks/subscription-health.md` |
| "Are certificates expiring? decryption / GP / inbound cert health" | `references/playbooks/certificate-expiry.md` |
| "Is User-ID working? can user/group rules match anyone?" | `references/playbooks/user-id-audit.md` |
| "Why can't host X reach service Y?" (live troubleshooting) | `references/playbooks/connectivity-troubleshoot.md` |
| "What changed / is it committed and pushed?" | `references/playbooks/change-review.md` |
| "Review admins, roles, and access" | `references/playbooks/access-review.md` |
| "Overview / health of the Panorama estate/fleet" | `references/playbooks/audit-estate.md` |

## General workflow

1. Determine the target (invariant 1).
2. Pick the playbook or reference that fits the ask.
3. Prefer a summary/count tool for the first read; drill in only where flagged.
4. On a Panorama, iterate device groups / templates and honor `timed_out`.
5. Report: lead with a verdict, then findings ranked by importance, then concrete
   next steps. Mark any un-assessed scope explicitly. Never propose a commit.

## Attribution

Original orchestration for the `panos` MCP server. PAN-OS NGFW domain framing was
informed by community work including `mukul975/Anthropic-Cybersecurity-Skills`
(`implementing-next-generation-firewall-with-palo-alto`, Apache-2.0).
