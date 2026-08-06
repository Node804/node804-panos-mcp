# Playbook: certificate & PKI expiry

Inventory the firewall's certificates and surface expiry and trust risks. Read-only.
Assumes the `panos-engineer` invariants.

Why it matters: an expired certificate breaks whatever depends on it — SSL
forward-proxy decryption stops (traffic fails open or closed depending on the
profile), the GlobalProtect portal/gateway rejects clients, and inbound-inspection
servers go dark. These fail on a date, not on a config change, so they're invisible
to a policy audit and to change review.

## Read

`mcp__panos__get_certificates` — every configured certificate with `name`,
`subject`, `issuer`, `common-name`, and `expiry-date` / `expiry-epoch`. On a
firewall this is the local store; on a Panorama it reads the appliance's own
certificates. For a managed firewall's certificates, target it via
`firewall=<name>`.

`expiry-epoch` is a Unix timestamp — use it for exact days-to-expiry math;
`expiry-date` is the human-readable form.

## Cross-reference (which certs actually matter)

A cert is only a risk if something uses it. Correlate:

- **Decryption certs** — the forward-trust / forward-untrust CA and any
  inbound-inspection certs referenced by decryption rules
  (`mcp__panos__get_decryption_rules`, or on Panorama the per-DG
  `mcp__panos__panorama_get_pre_rules` / `mcp__panos__panorama_get_post_rules`
  with `rule_type="decryption"`). An expired forward-trust CA breaks all outbound
  decryption. See `../decryption.md`.
- **GlobalProtect certs** — portal/gateway server certs
  (`mcp__panos__get_globalprotect_config`). Expiry locks users out. See
  `../routing-vpn.md`.

## Analysis

- **Expired:** past `expiry-epoch` now — active outage or open blind spot. Top
  finding.
- **Expiring soon:** within ~30/60/90-day bands — plan replacement; a CA cert
  deserves more lead time than a leaf.
- **Self-signed where CA-signed is expected:** portal/gateway server certs that are
  self-signed cause client trust prompts/failures.
- **Trust-chain gaps:** an issuer whose CA isn't present, or a forward-trust CA not
  actually deployed to endpoints (can't verify endpoint trust from here — note it as
  an assumption to check).
- **Orphaned certs:** present but referenced by no rule/profile — low risk, hygiene
  only.

## Flag

Any expired certificate in active use; certs expiring inside your change-lead-time
window; self-signed server certs on GP/inbound; forward-trust/untrust CA nearing
expiry.

## Report

Lead with the count expired / expiring-30 / expiring-90 and whether any is in active
use. Table the at-risk certs with days-to-expiry and their consumer (decryption / GP
/ inbound / unused). Separate "in use" from "orphaned". State whether you read a
firewall or the Panorama appliance. Read-only — recommend renewal, never rotate.
