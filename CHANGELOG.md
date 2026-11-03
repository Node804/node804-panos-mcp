# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-11-03

### Added — `node804-panos-mcp-setup` install wizard

A bundled setup wizard that configures the server end to end, so a new install
no longer means hand-editing JSON. Run `node804-panos-mcp-setup` (or
`python -m panos_mcp.setup` if the console script isn't on `PATH`).

- **Secure by default** — stores the API key in the OS keychain (Windows
  Credential Manager / macOS Keychain / Linux Secret Service) and writes only
  `name` + `host` to `firewalls.json`. The key is read with `getpass` and never
  echoed or written to a plaintext config.
- **Per-client, extensible** — each AI client is its own yes/no question (Claude
  Desktop today; new clients are a single `AgentSetup` entry). The Claude Desktop
  step backs up the config first and writes a server entry with no host or key in
  it (both resolve from the keychain + `firewalls.json`).
- **Skill install** — the `panos-engineer` skill is bundled into the wheel and
  installed by the wizard: copied into `~/.claude/skills` for Claude Code and
  zipped for Claude Desktop / claude.ai upload.
- **Subcommands** — `skill` (install/upgrade the skill only, e.g. after
  `pip install -U`), and `firewall list` / `add` / `remove` to manage
  `firewalls.json` without the full wizard. The wizard is modify-aware: it lists
  existing entries and lets you skip the firewall step on a re-run.
- Non-interactive mode via flags + `PANOS_SETUP_API_KEY` for scripted rollout.
- New `remove_firewall_entry()` in the firewall registry (deletes the entry and
  its keychain key).

## [0.1.8] — 2026-11-03

### Documentation

Documentation-only release to refresh the PyPI project page.

- **README** — the Claude Desktop setup now shows both `uvx` and `pip` configs
  as parallel options (previously a one-line pip aside). Added a **ChatGPT**
  section (ChatGPT desktop app custom-MCP form, the web stdio-bridge caveat, and
  OpenAI Codex CLI / `config.toml` setup). The skill install is now inlined under
  each client (Claude Desktop, Claude Code, ChatGPT/Codex) instead of a separate
  trailing section, so configuring the server and installing the `panos-engineer`
  skill read as one task per client.
- No code changes; the server behaves identically to 0.1.7.

## [0.1.7] — 2026-08-06

### Fixed — Advanced Routing Engine firewalls silently reported zero routes (P0)

`get_routing_table` issued only the legacy virtual-router operational command
(`<show><routing><route/></routing></show>`). On a firewall running the
**Advanced Routing Engine** (ARE, PAN-OS 10.2+, default on new deployments in
current releases) that command is still *valid* — PAN-OS walks an empty legacy
RIB and returns a well-formed empty response. No error, nothing to catch. The
tool returned `{"total": 0, "items": []}` on a box with a fully populated ARE
RIB, and an AI caller reasonably concluded the firewall had no routes.

Both route readers are now routing-engine aware and read the ARE stack directly.

- **`detect_routing_engine`** (`tools/_common.py`) — reads the
  `deviceconfig/setting` advanced-routing flag (accepting both the
  `advance-routing` config spelling and `advanced-routing`), falling back to the
  presence of `network/logical-router` entries. Memoized per client, so a
  session pays for it once per device. Detection is config-based by necessity:
  the legacy command's success-but-empty behavior makes try-and-catch useless.
  A probe that fails or times out falls back to `legacy` — the pre-existing
  behavior — so detection can never make a working firewall worse.
- **`routing_engine`** (`legacy` / `advanced`) is now reported by
  `get_routing_table` and `get_static_routes` on every firewall response. It is
  omitted for a Panorama target: the engine is a per-device (and per-template)
  setting, so the appliance has no single answer, and a guess would be worse
  than silence.
- **`get_routing_table` reads the ARE RIB** on an ARE firewall
  (`<show><advanced-routing><route/></advanced-routing></show>`). Unlike every
  other PAN-OS op command this one returns **FRR's native JSON inside a
  `<json>` element**, not XML rows — ARE is FRRouting underneath. The payload is
  normalized into the same lean row shape as legacy, gaining `protocol` (legacy
  buries this in the `flags` glyphs), `vrf`, and `logical_router`. ECMP routes
  fan out to one row per nexthop, matching how the legacy table represents
  multipath, so a two-path route can't collapse into one row that hides half its
  nexthops. Directly-connected routes report `nexthop: "connected"` rather than
  omitting the field, keeping the row list schema-consistent.
  **Note:** ARE `flags` come from FRR and use a different alphabet than legacy
  PAN-OS route flags. Don't write a flag filter that assumes either.
- **An unparseable ARE payload returns an error, never an empty list** — the one
  degradation that would resurrect the original bug in a new costume.
- **`get_static_routes` reads logical routers and VRFs** on an ARE firewall via
  pan-os-python's `LogicalRouter` / `Vrf` / `VrfStaticRoute(V6)` models, tagging
  each row with `vrf` and `logical_router`. `virtual_router` is matched against
  VRF names; when it matches none, **every** VRF is returned rather than
  nothing, so passing a legacy VR name to an ARE box can't produce a misleading
  empty result.
- **The Panorama template walk now reads both engines.** The routing engine is a
  per-template setting, so a managed estate can be legitimately mixed; the walk
  reads the virtual-router *and* logical-router trees and tags every row with
  its own `routing_engine` alongside the existing `template` tag. Previously it
  read only the legacy tree and silently dropped every ARE template's routes.
- **`add_static_route` / `delete_static_route` now refuse on an ARE firewall.**
  This was the most dangerous case: `network/virtual-router` is a *writable*
  subtree on an ARE box, so the candidate config accepts the route and the
  commit succeeds — but ARE never reads it and the route never enters the RIB.
  The operator was told the change landed when it had not. VRF-aware writes
  (`network/logical-router`) are not yet supported; the guard names the
  limitation instead of failing silently.
- `SHAPE_ROUTE` and `SHAPE_STATIC_ROUTE` gained the ARE scope fields. They are
  absent on legacy rows and dropped by the shaper, so legacy responses are
  byte-identical to before.
- The `panos-engineer` skill's routing reference documents the engine field, the
  differing flag alphabet, the VRF-filter fallback, and the write refusal, so an
  agent doesn't report "no routes configured" on an ARE device.

Reported against a PA-440 on PAN-OS 12.1.3-h3 with ARE enabled.

Response-shape credit: the `<json>`-wrapped FRR payload was confirmed against
`get_are_routes()` in Palo Alto's own
[pan-os-upgrade-assurance](https://github.com/PaloAltoNetworks/pan-os-upgrade-assurance),
and the config tree against pan-os-python's ARE models. Two details remain
unverified against live ARE hardware: the config spelling of the enable flag
(both `advance-routing` and `advanced-routing` are accepted, and the
logical-router probe stands alone regardless), and the nexthop key for
non-directly-connected routes (`ip` is read, with `ipv6` as a fallback).

### Added — serial-through-Panorama connections (`PANOS_ALLOW_SERIAL_CONNECTION`)

Reach every Panorama-managed firewall through a **single Panorama connection**,
with no per-device API keys. When `PANOS_ALLOW_SERIAL_CONNECTION` is enabled and
the configured connection is a Panorama, any `firewall` argument that isn't a
configured entry is resolved against Panorama's live `show devices all`
inventory (matched by hostname *or* serial) and the call is routed through
Panorama using the device's serial as the API `target`
(pan-os-python's `Firewall(serial=…)` proxying). One Panorama key covers the
whole fleet.

- **Off by default**, gated behind `PANOS_ALLOW_SERIAL_CONNECTION` (truthy:
  `true`/`1`/`yes`/`on`). The Claude/MCP settings only need to point at Panorama.
- **Direct entries always win.** A `firewalls.json` entry or `PANOS_HOST` env
  target with its own key connects straight to the device and is used in
  preference to a managed device of the same name — so a box stays reachable
  even if Panorama is down.
- **Explicit serial entries** are also supported in `firewalls.json`:
  `{ "name": "hq-fw", "serial": "0123…", "via": "panorama" }` (omit `via` to use
  the default connection). These carry no key of their own.
- Disconnected managed devices and unknown names return a clean, actionable
  error instead of a confusing failure.
- `list_firewalls` now reports `serial_connection` and, when enabled, a
  `managed_devices` inventory (hostname, serial, connected) excluding names
  already configured directly. `server_status` reports the flag under
  `firewalls.serial_connection`.

### Fixed — Panorama appliances were silently detected as Firewalls (P0)

`_build_client` probed the device type by calling `refresh_system_info()` on a
`Firewall` object. The `Firewall` subclass's `_save_system_info` parses
firewall-only fields — `app-version` and `multi-vsys` — that a Panorama's
`show system info` does **not** return, so the probe raised
`KeyError: 'multi-vsys'` *before* the model could be inspected. That exception
was caught and the appliance was cached as a `Firewall` — so on a Panorama
target **every** `isinstance(client, Panorama)` check returned `False`:

- the redirect guards (`summarize_security_policy`, `count_rules_by_action`,
  `find_rule_by_name`, `get_decryption_rules`, …) didn't fire and returned
  misleading empty/zero results instead of steering to the `panorama_*` sibling;
- the reject guards (`get_routing_table`, `get_interfaces`, …) didn't fire and
  either issued a dataplane command Panorama rejects (raw device error) or
  returned a misleading empty list;
- the scope-aware and template-aware readers took the firewall-local branch and
  saw only `shared`/`vsys1` (empty on a Panorama);
- serial-through-Panorama resolution reported "no Panorama connection available".

The explicit `panorama_*` tools kept working because they issue Panorama/
device-group-scoped xpath queries directly, which are valid against a Panorama's
config tree regardless of the Python client class — which is why the fault
looked like a guard regression rather than a detection failure.

Detection now probes with the **class-neutral** `show_system_info()` (the raw
`show system info` dict, no subclass field parsing), reads the model, and *then*
constructs the correct `Panorama`/`Firewall` class. Confirmed live against a
Panorama (model `Panorama`, PAN-OS 11.2.10-h3): the guards fire and the
scope-aware/template-aware walks iterate every device group and template.
Regression test added
(`test_client.py::test_panorama_detected_when_firewall_refresh_would_raise`).

This one fix also closed the two sibling P0s that shared the predicate:
scope-/template-aware readers returning empty on Panorama
(`count_objects_by_type`, `get_address_groups`, `get_security_profiles`,
`get_zones`, `get_static_routes`), and serial-through-Panorama being inert.

### Fixed — serial-through-Panorama device discovery sent a malformed op

`_fetch_device_map` issued `pano.op("<show><devices><all>…</show>")` without
`cmd_xml=False`. pan-os-python's `op()` defaults to `cmd_xml=True`, which treats
the argument as a CLI-style string and re-encodes it, so PAN-OS rejected the
already-XML payload with HTTP 400 "Request is not a valid XML". This broke
`list_firewalls`' managed-device inventory and every serial redirect
(`get_*(firewall="<managed-device>")`). The call was previously unreachable —
the Panorama-detection bug above meant `_default_panorama` returned `None` and
short-circuited before any op ran — so fixing detection exposed it. Now sends
verbatim XML via `cmd_xml=False`, matching `op_to_dict`. The device-map test
now asserts the call convention. Confirmed live: 8 managed devices enumerate and
serial redirect reaches them.

### Fixed — phantom `vsys1`/`dlp` entries in the managed-device inventory

`_iter_device_entries` parsed the `show devices all` response with a recursive
`.//entry` match, so the per-device nested `vsys/entry` (`vsys1`) and
`plugin_versions/entry` (`dlp`) were mistaken for managed devices and surfaced
as bogus, permanently-disconnected rows in `list_firewalls`. Both the Element
and parsed-dict paths are now scoped to the `devices` container's direct `entry`
children (`.//devices/entry`). Regression test added. Confirmed live: only real
firewalls are listed.

### Fixed — config xpath reads with spaces in names (e.g. "Lafayette Plant")

Config-by-xpath reads were wrapped in a `<show><config><running><xpath>` **op**
command, which PAN-OS CLI-tokenizes — so a predicate value containing a space
(`entry[@name='Lafayette Plant']`) was truncated at the space and the device
returned "No such node". This silently affected `get_config_xpath` and, on
Panoramas with space-named device groups/templates, the per-DG/template xpath
readers (decryption & security profiles, dns-proxy / GlobalProtect / User-ID
template walks, admin roles, collector groups, QoS). `refreshall`-based tools
were unaffected because pan-os-python reads them through the dedicated xpath
API.

All config-xpath reads now go through that same API via a new
`config_xpath_to_dict` helper (`xapi.show(xpath=...)`), which passes the
predicate value as a structured parameter — names with spaces resolve
correctly. The op-command form is no longer used for config reads. Confirmed
live: `get_config_xpath` against `…/device-group/entry[@name='Lafayette
Plant']/…` previously returned "No such node" and now returns the subtree.

### Fixed — server hang on slow/stuck device calls

A blocking PAN-OS API call could freeze the entire MCP process — even local
tools like `server_status` stopped responding — and stay frozen for up to 20
minutes. Two compounding root causes:

- **No request timeout.** pan-os-python defaults its per-HTTP-request timeout
  to 1200s (20 minutes). The client factory now sets a bounded timeout
  (default 60s, override with `PANOS_API_TIMEOUT`) on every constructed
  client *before* the xapi is built — pan-os-python builds the xapi lazily and
  caches it, so a timeout set afterward does not take effect. This is a
  per-request bound; commits/pushes submit a job then poll with short
  requests, so it does not truncate a long commit.
- **Read tools blocked the event loop.** The write tools already offload their
  synchronous pan-os-python calls via `run_blocking` (thread executor), but the
  read tools called pan-os-python directly inside their async handlers, so one
  stuck call froze the whole asyncio loop. The certificate/decryption reads
  (`get_certificates`, `get_decryption_rules`, `get_decryption_profiles`) now
  offload through `run_blocking` and stay responsive.

`get_decryption_profiles` also no longer mistakes a genuine transport failure
(timeout, connection reset) for an empty profile set — only PAN-OS "No such
node" is treated as empty; other errors are surfaced.

The decryption-profile config read is itself a known hang risk on some targets
(the query goes out and never completes), with no internal bound shorter than
the client-level request timeout. It now runs under an explicit, short,
asyncio-enforced per-fetch timeout (`PANOS_PROFILE_FETCH_TIMEOUT`, default 20s)
via the new `run_blocking_timeout` helper, returning a clean timeout error
promptly instead of hanging until the client timeout fires.

This was exposed by the decryption-profile fix below: it replaced an instant
"not modeled" short-circuit with a real (previously un-timed-out, on-loop)
config fetch.

The Panorama **multi-call read walkers** — the worst case, since they issue
`|DGs| × types × 2` sequential blocking calls — now run each sub-query off the
loop under a short per-call timeout (`PANOS_READ_TIMEOUT`, default 30s) via the
new `run_blocking_timeout` / `read_timeout` helpers:

- `panorama_walk_all_rules` and `panorama_count_rules_per_device_group`: a
  stuck `(device_group, rulebase, rule_type)` sub-query is **skipped** and
  recorded in a new `timed_out` list in the response, so one hanging rulebase
  yields partial results plus an explicit note instead of stalling the walk.
- `panorama_summarize_security_policy`: same treatment; skipped rulebases are
  listed in `timed_out`.
- The per-DG/shared readers (`panorama_get_pre_rules`/`post_rules`,
  `panorama_get_device_group_nat_rules`, the device-group/shared object
  readers, and `_find_dg`) now offload + bound their single calls and return a
  clean timeout error rather than hanging.

Remaining single-call op-command read tools (interfaces, logs, etc.) still run
on the loop, bounded by the client-level per-request timeout; a follow-up pass
can route them through the same helper.

### Changed — object & template readers are scope-aware on Panorama

Closes the silent-incomplete and silent-empty traps for the remaining
firewall-scoped readers by making them walk all Panorama scopes instead of just
the shared/local one. Firewall behavior is unchanged (single read, no scope/
template tag); each per-scope read is offloaded and bounded, and a scope that
times out is skipped and listed in `timed_out`.

- **Object/profile readers** (`gather_scoped_objects`): `get_address_objects`,
  `get_address_groups`, `get_service_objects`, `get_service_groups`, `get_tags`,
  `get_application_filters`, `get_security_profile_groups`, `get_security_profiles`,
  plus `find_address_object` and `count_objects_by_type`. On a Panorama these now
  walk `shared` + every device group, tagging each item with its `scope`
  (`"shared"` or the device-group name). Previously they read only shared and
  silently omitted every device group.
- **Template-scoped network readers** (`gather_template_objects` /
  `gather_template_config`): `get_zones`, `get_vlans`, `get_static_routes`
  (via the object model) and `get_dns_proxy`, `get_globalprotect_config`,
  `get_userid_config` (via xpath). On a Panorama these now walk every template,
  tagging each item with its source `template` — previously they returned empty
  (or errored) because templates were never read. `get_userid_config` also stops
  being a permanent "not modeled" stub (it reads via xpath now).

A `scope` / `template` field was added to the affected lean shapes; it's
populated only on Panorama, so firewall responses are byte-for-byte unchanged.

### Changed — firewall-scoped policy/aggregation readers redirect on Panorama

Extends the `get_decryption_rules` redirect to the rest of the family. These
tools read the firewall-local rulebase/vsys config, which is empty (or errors)
on a Panorama — so an agent auditing policy got a confidently-wrong "nothing
configured" answer. On a Panorama target they now return a clean error naming
the correct device-group tool (via the shared `redirect_panorama_to_sibling`
guard); firewall behavior is unchanged.

- `get_security_rules`, `get_nat_rules`, `get_pbf_rules` → point to
  `panorama_get_pre_rules` / `panorama_get_post_rules` (with `rule_type`) and
  `panorama_get_device_group_nat_rules`.
- `get_admin_roles` → `panorama_get_admin_roles` (previously raised an uncaught
  "No such node"); `get_qos_rules` → firewall target / `get_config_xpath`
  (no Panorama QoS tool; previously raised "No such node").
- `summarize_security_policy` → `panorama_summarize_security_policy`;
  `count_rules_by_action` → `panorama_count_rules_per_device_group`;
  `find_rule_by_name` → `panorama_walk_all_rules`.

Still returning silent shared-only/incomplete results on Panorama (a separate
follow-up): the object readers (`get_address_objects`, `get_tags`, …) and the
template-scoped network readers (`get_zones`, `get_static_routes`, …).

### Changed — Panorama-target guarding for per-firewall tools

The per-firewall **dataplane/runtime** read tools now return a clean,
actionable error when pointed at a Panorama target instead of a misleading
empty result (which read as "nothing configured"). A shared
`reject_panorama_target` guard backs `get_interfaces`, `get_routing_table`,
`get_arp_table`, `get_dhcp_leases`, `get_ipsec_tunnels`,
`get_globalprotect_users`, `get_userid_mappings`, `get_userid_groups`,
`get_wildfire_status`, `get_rule_hit_counts`, and `unused_rules`; each error
points the caller at the `firewall` parameter. `get_active_sessions` and the
`diagnostics` tools already guarded. `get_system_resources` is intentionally
**not** guarded — Panorama has its own CPU/memory and answers that command.

### Added — Panorama siblings for device-group / shared config

Toward full feature parity for Panorama-only operators:

- **Device-group object readers** (per-DG counterparts to the firewall
  `get_*` tools): `panorama_get_device_group_address_objects`,
  `…_address_groups`, `…_service_objects`, `…_service_groups`,
  `…_application_filters`, `…_profile_groups`. Each takes a `device_group`
  and reads that DG's objects; the existing `panorama_get_shared_*` tools
  cover the shared scope.
- **Shared object readers** filling gaps that had no Panorama tool at all:
  `panorama_get_shared_tags`, `panorama_get_shared_application_filters`.
- **`panorama_get_admin_roles`** — admin role definitions at the Panorama
  level (the per-firewall `get_admin_roles` reads a vsys1 xpath that misses
  them). `get_admins` already works against Panorama, so no separate tool was
  added for it.

### Fixed — decryption read paths

- **`get_decryption_profiles`** no longer dead-ends, and is now scope-aware.
  `DecryptionProfile` is not in pan-os-python's object model in any release, so
  the tool no longer tries to import it (the import always failed, returning
  the "not modeled" stub). It reads the running config directly via xpath,
  scoped to the target:
    - **Firewall** → the `vsys1` tree and the `shared` tree.
    - **Panorama** → the `shared` tree plus **every device group's** tree. The
      previous version only checked shared + the firewall-shaped `vsys1` path,
      so on a Panorama it returned an empty set even when device groups held
      the profiles. Device-group enumeration runs under the bounded timeout.
  Every profile carries a `scope` field (`"shared"`, a device-group name, or
  `"vsys1"`) identifying where it lives; profiles are not de-duplicated across
  scopes (a same-named profile in two scopes is two distinct objects). Each
  per-scope fetch is offloaded and bounded by an asyncio timeout
  (`PANOS_PROFILE_FETCH_TIMEOUT`, default 20s): a scope that times out is
  skipped and listed in `timed_out`, a real (non-"No such node") failure is
  listed in `errors`, and the rest of the walk still returns — so one stuck
  device group can't hang the call or blank the result. PAN-OS "No such node"
  is treated as empty, and the entry `@_name` attribute is promoted to a plain
  `name` key so the lean shape and pattern filter behave like the modeled
  tools.
- **`get_decryption_rules` now redirects on a Panorama target** instead of
  returning a misleading empty list. It reads the firewall-local rulebase,
  which is empty on a Panorama — so an agent asked to evaluate SSL Forward
  Proxy / decryption would get "no rules" and wrongly conclude decryption
  isn't configured. Against a Panorama it now returns an error naming the
  correct tools (`panorama_get_pre_rules` / `panorama_get_post_rules` with
  `rule_type="decryption"`), and its description marks it firewall-only. Backed
  by a reusable `redirect_panorama_to_sibling` guard (firewall behavior
  unchanged). The Panorama pre/post-rule docstrings gained the "SSL decryption
  / SSL Forward Proxy" wording so tool-selection favors them for those queries.
- **`panorama_get_pre_rules` / `panorama_get_post_rules`** gained a
  `rule_type` parameter (`"security"` default, plus `"nat"`, `"pbf"`,
  `"decryption"`) — a single `refreshall` against the requested device-group
  rulebase. Both tools share one parametric helper driven by the existing
  `_RULE_TYPE_REGISTRY`; security rules keep their inspection/log enrichment,
  and each type is projected by its own lean shape. The default call
  (`rule_type` omitted) is unchanged. The per-DG `refreshall` runs off the
  event loop under the bounded read timeout — the same treatment
  `panorama_walk_all_rules` applies to its per-(DG, rulebase, type) reads — so
  a stuck rulebase returns a clean timeout error instead of hanging. The
  docstrings no longer claim this path is preferable to / more reliable than
  the walker: for decryption the two read the same data and are equally
  bounded; use the per-DG tools for one device group and the walker to sweep
  many.

## [0.1.6] — 2026-06-11

### Added — live troubleshooting

Nine tools that close the gap between auditing policy and actually
troubleshooting it. The read-only ``<test>`` operational commands are now
first-class ``Mode.READ`` tools instead of being reachable only through the
ADMIN-gated raw-op escape hatch.

- **`test_security_policy_match`** — which security rule a flow matches, the
  live ``test security-policy-match``. Answers "is traffic from X to Y
  allowed, and by which rule?" without changing state.
- **`test_nat_policy_match`** — matching NAT rule and the resulting
  translation.
- **`test_routing_fib_lookup`** — egress interface / next-hop for a
  destination (``test routing fib-lookup``).
- **`get_sessions`** — filtered live session table (``show session all filter
  ...``) by source / destination / port / protocol / application, with the
  NAT-translation fields (``xsource``, ``xdst``, ``xdport``, ``nat``) in the
  lean view.
- **`get_session_detail`** — full per-session record (``show session id N``).
- **`get_pending_changes`** — uncommitted candidate changes
  (``show config list changes``); the "is anything staged?" check to run
  before ``commit``.
- **`get_config_diff`** — entry-level candidate-vs-running diff at an XPath
  (added / removed / modified), so the staged-write workflow is reviewable
  before commit. Subject to the same read-side denylist as
  ``get_config_xpath``.
- **`get_rule_hit_counts`** — per-rule hit counts and last-hit timestamps
  (``show rule-hit-count``).
- **`unused_rules`** — security rules with zero hits, joined with the
  rulebase for disabled status — a ready cleanup worklist.
- **`revert_config`** (ADMIN) — discard all uncommitted candidate changes,
  reverting to the running config; audited, with a loud warning that it
  discards every admin's staged work.

Source/destination IP inputs to the diagnostics tools are validated as bare
IP addresses; all interpolated values are XML-escaped. The per-firewall ops
return a clear error when pointed at a Panorama target.

## [0.1.5] — 2026-06-11

First public release, published to PyPI as **`node804-panos-mcp`**.

### Security

- **XPath injection hardening (`get_config_xpath`).** LLM-supplied xpaths are
  now XML-escaped and the schema rejects angle brackets, so a value can no
  longer break out of the `<xpath>` element to inject sibling op-command XML.
  All `<show><config><running>` command construction is centralized in
  `build_running_config_xpath_cmd`, so the escaping can't be dropped by a
  refactor.
- **Read-side denylist.** `get_config_xpath` and `run_show_command` now refuse
  reads of secret-bearing config subtrees (certificates, `mgt-config` admin
  accounts/password hashes, authentication profiles), mirroring the existing
  write-side denylist.
- **License authcodes** are no longer returned in the default `get_licenses`
  response — pass `verbose=true` or `fields=["authcode"]` to include them.

### Packaging

- Renamed the distribution to `node804-panos-mcp` and declared its dependency
  on `node804-mcp-toolkit` (previously installed out-of-band). The version is
  now single-sourced from `panos_mcp.__version__`. Added a `py.typed` marker,
  trove classifiers, keywords, and an sdist exclude list. CI installs the
  declared dependency instead of an unclaimed PyPI name.

### Fixed

- `panorama_summarize_security_policy` no longer pre-rejects legitimate
  Panorama targets with a redundant `isinstance` gate that misfired when
  the resolved client's class didn't identity-match the locally-imported
  `Panorama` symbol. Sibling tools (`panorama_count_rules_per_device_group`,
  `panorama_walk_all_rules`) trust resolution; this one now does too, and
  surfaces a clean error if `DeviceGroup.refreshall` actually fails.

### Changed (breaking)

- Renamed the derived security-rule audit boolean **`has_profile` →
  `has_inspection`** on every rule listing (lean default field) and the
  matching aggregate **`rules_without_profiles` → `rules_without_inspection`**
  in `summarize_security_policy` / `panorama_summarize_security_policy`. The
  old flag computed `bool(group) or bool(profile_setting)`, but
  `profile_setting` is never a top-level key on a `SecurityRule.about()`
  dict — so the flag effectively meant "is there a profile *group*?" and
  reported every individual-profile-attachment rule (a common Panorama
  pattern: `virus`, `spyware`, `vulnerability`, `url_filtering`,
  `file_blocking`, `data_filtering`, `wildfire_analysis` set directly)
  as "no inspection". The new flag is true when any of those individual
  fields is set OR a profile group is bound. Anyone who filtered with
  `attrs={"has_profile": "false"}` to find rules missing inspection was
  getting confidently wrong results in environments that don't use
  profile groups; update such filters to `attrs={"has_inspection": "false"}`.

## [0.1.0] — 2026-05-13

Initial release. 123 tools across 14 categories, built on
[`pan-os-python`](https://github.com/PaloAltoNetworks/pan-os-python) and the
[`node804-mcp-toolkit`](https://github.com/Node804/node804-mcp-toolkit) shared utilities
package.

### Added — RBAC and security posture

- **Default-deny RBAC** via `PANOS_MODE` with four tiers: `read` (default, 76
  tools), `standard` (+10 object/tag CRUD), `full` (+31 rule CRUD), `admin`
  (+6 commit/push/raw-API tools).
- **TLS verification on by default**. Opt out via `PANOS_TLS_VERIFY=false` or
  trust a custom CA via `PANOS_TLS_CA=/path/to/ca.pem`.
- **Audit logging** to a JSON-lines file via `PANOS_AUDIT_LOG=`. Captures one
  event per tool call with sanitized arguments (api_key/password/secret/token
  redacted at any depth), timing, and error state.
- **Multi-firewall registry** in `~/.config/panos-mcp/firewalls.json` (override
  with `PANOS_FIREWALLS_CONFIG`). API keys live in the OS keychain via the
  `keyring` package; the JSON file holds only names and hosts.
- **Plaintext-to-keychain auto-migration** on first load — older configs with
  inline `api_key` fields are migrated to the keychain and the JSON is
  rewritten without them. Headless Linux servers without a keychain backend
  fall back to plaintext storage with `0o600` file permissions.
- **Input validation**: rule, object, tag, device-group, and virtual-router
  names restricted to PAN-OS-safe charset (letters, digits, dot, underscore,
  hyphen, space) at the schema layer — defends against XPath injection before
  reaching pan-os-python.
- **XML escaping** of user-supplied values in the QoS xapi fallback path
  (`tools/_xml_writers.py`), via `xml.sax.saxutils.escape`.

### Added — Token efficiency

- **Lean responses by default.** Every list-returning tool exposes only the
  fields most relevant to its purpose; verbose responses are opt-in via
  `verbose=True`.
- **Shared parameters from mcp-toolkit**: `verbose`, `fields` (projection),
  `pagination.limit` / `pagination.offset`, `pattern` (server-side substring
  filter). Same names across every tool.
- **Aggregation tools** that replace dump-and-grep with focused queries:
  `count_rules_by_action`, `find_rule_by_name`, `find_address_object`,
  `summarize_security_policy`, `count_objects_by_type`.
- **Regression-guarded benchmark suite** in `tests/benchmark/` asserting
  measured savings (e.g. `summarize_security_policy` is 338× smaller than
  verbose `get_security_rules`, `find_address_object` is 241× smaller than
  dumping address objects). Run with `pytest -m benchmark`.

### Added — Tool surface (123 tools)

- **System (4)**: `get_firewall_info`, `get_ha_status`, `get_active_sessions`,
  `get_system_resources`.
- **Network (10)**: 8 reads (interfaces, zones, routing, ARP, VLANs, DHCP,
  DNS proxy, static routes) + 2 CRUD (`add_static_route`,
  `delete_static_route`).
- **Security (18)**: 6 reads (rules, profiles, profile groups, PBF, DoS, QoS)
  + 12 CRUD covering security/PBF/QoS rule add/delete/move/set_disabled.
- **Objects & tags (16)**: 6 reads (address/service objects + groups,
  application filters, tags) + 10 CRUD for the same.
- **NAT (5)**: 1 read + add/delete/move/set_disabled.
- **User-ID (3)**: mappings, groups, agent config.
- **Administrators (3)**: admin accounts, role definitions, auth profiles.
- **VPN (3)**: IPSec tunnels, GlobalProtect users, GlobalProtect config.
- **Panorama (29)**: 20 reads (managed devices, device groups, templates,
  shared objects, pre/post rules, log collectors, push/commit status, HA,
  device-group hierarchy) + 9 rule CRUD (pre/post/DG-NAT).
- **Logs (5)**: traffic, threat, system, config, URL filter.
- **Threat & content (4)**: WildFire status, AV signatures, content versions,
  URL categories.
- **Certificates (7)**: 3 reads + 4 decryption rule CRUD.
- **Licenses (2)**: license info, usage details.
- **Utility (2)**: `get_config_xpath` (read), `run_op_command` (admin).
- **Server diagnostic (2)**: `server_status`, `list_firewalls`. Always
  available, even in `read` mode.
- **Aggregations (5)**: see Token efficiency above.
- **Commit & raw API (5, admin-only)**: `commit`, `panorama_commit`,
  `panorama_push_to_devices`, `set_config`, `delete_config`.

### Notes

- pan-os-python 1.12.x still imports the removed-in-Python-3.12 `distutils`
  module. The package shims it from `setuptools._distutils` in
  `panos_mcp/__init__.py` before any pan-os-python import. When
  pan-os-python ships a 2.0 that drops the legacy import, the shim becomes
  a no-op and can be removed.
- pan-os-python 1.12.5 doesn't model QoS rules. QoS CRUD tools fall back to
  `client.xapi.set/delete/move/edit` with hand-built XML
  (`tools/_xml_writers.py`), using `xml.sax.saxutils.escape` on every
  interpolated value. Deletable when pan-os-python adds first-class QoS.
- A handful of read tools (`get_dos_profiles`, `get_certificates`,
  `get_decryption_profiles`, `get_userid_config`) include guarded
  `ImportError` stubs for pan-os-python classes that may not exist on all
  versions. These auto-upgrade to native modeling when present.

### Verification

- 227 unit tests + benchmark suite passing on Python 3.13/3.14
- Ruff (`E F I B UP SIM RUF`), `ruff format`, and mypy (`--strict`) clean
  across all source files
- POSIX file-permission tests skipped on Windows; everything else runs on
  every platform

[Unreleased]: https://github.com/Node804/node804-panos-mcp/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/Node804/node804-panos-mcp/releases/tag/v0.1.6
[0.1.5]: https://github.com/Node804/node804-panos-mcp/releases/tag/v0.1.5
[0.1.0]: https://github.com/Node804/node804-panos-mcp/releases/tag/v0.1.0
