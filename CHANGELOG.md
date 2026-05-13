# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-05-13

Initial release. 123 tools across 14 categories, built on
[`pan-os-python`](https://github.com/PaloAltoNetworks/pan-os-python) and the
[`mcp-toolkit`](https://github.com/epopleachim/mcp-toolkit-py) shared utilities
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

- 134 unit tests + 7 benchmark tests passing on Python 3.13/3.14
- Ruff (`E F I B UP SIM RUF`) and mypy (`--strict`) clean across 30 source
  files
- POSIX file-permission tests skipped on Windows; everything else runs on
  every platform

[Unreleased]: https://github.com/epopleachim/panos-mcp-py/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/epopleachim/panos-mcp-py/releases/tag/v0.1.0
