"""FastMCP server entrypoint for panos-mcp.

Phase 3: full read-only tool surface plus the always-on diagnostic tools.
71 read tools across system / network / security / objects / NAT / user-id /
admin / VPN / Panorama / logs / threat / certificates / licenses / utility,
each with default-lean responses (verbose=true to opt out) and pagination /
pattern filtering.

Environment variables:

| Var                          | Purpose                                                |
|------------------------------|--------------------------------------------------------|
| ``PANOS_MODE``               | RBAC mode (read/standard/full/admin). Default: read.   |
| ``PANOS_AUDIT_LOG``          | Path to JSON-lines audit log. Unset = audit disabled.  |
| ``PANOS_TLS_VERIFY``         | true (default) / false / 1 / 0 / yes / no.             |
| ``PANOS_TLS_CA``             | Optional path to a custom CA PEM bundle.               |
| ``PANOS_FIREWALLS_CONFIG``   | Override path for firewalls.json.                      |
| ``PANOS_HOST``               | Single-firewall fallback hostname.                     |
| ``PANOS_API_KEY``            | Single-firewall fallback API key.                      |
| ``PANOS_ALLOW_SERIAL_CONNECTION`` | Default-off opt-in. When on and the configured    |
|                              | connection is a Panorama, any ``firewall`` name that   |
|                              | isn't a direct entry is resolved against Panorama's    |
|                              | live device inventory and reached through Panorama by  |
|                              | serial — one Panorama key covers the whole managed     |
|                              | fleet. Direct entries always take precedence.          |
| ``PANOS_ENABLE_RAW_CONFIG``  | Default-off opt-in for ``set_config``/``delete_config``|
|                              | escape hatches.  Even when on, an xpath denylist still |
|                              | blocks ``/mgt-config``, ``/shared/certificate``, HA.   |
| ``PANOS_RAW_XPATH_ALLOW``    | Optional comma-separated xpath prefix allow-list.      |
|                              | When set, raw-config calls outside these prefixes are  |
|                              | rejected.                                              |
| ``PANOS_ENABLE_RAW_OPS``     | Default-off opt-in for the generic ``run_op_command``  |
|                              | tool.  ``run_show_command`` is always available; the   |
|                              | gated variant additionally accepts non-show verbs,     |
|                              | subject to a built-in denylist (reboot, software       |
|                              | install, debug, credential mutation, etc.).            |
"""

from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, describe_tls, open_sink, resolve_tls_config

from . import __version__
from .config.firewalls import load_firewall_config, serial_connection_enabled
from .tools._common import ToolContext
from .tools.admin import register_admin_tools
from .tools.admin_ops import register_admin_ops_tools
from .tools.aggregations import register_aggregation_tools
from .tools.certificates import register_certificates_tools
from .tools.diagnostics import register_diagnostics_tools
from .tools.firewalls import register_firewall_tools
from .tools.licenses import register_licenses_tools
from .tools.logs import register_logs_tools
from .tools.nat import register_nat_tools
from .tools.network import register_network_tools
from .tools.objects import register_objects_tools
from .tools.panorama import register_panorama_tools
from .tools.security import register_security_tools
from .tools.status import register_status_tools
from .tools.system import register_system_tools
from .tools.threat import register_threat_tools
from .tools.userid import register_userid_tools
from .tools.utility import register_utility_tools
from .tools.vpn import register_vpn_tools

# --- Toolkit-driven setup ---------------------------------------------------

audit_sink = open_sink(env_var="PANOS_AUDIT_LOG")
"""Where audit events go. No-op when PANOS_AUDIT_LOG is unset."""

tls_config = resolve_tls_config(dict(os.environ), prefix="PANOS")
"""TLS verification config. Verify-by-default."""

gate = ModeGate.from_env(
    env_var="PANOS_MODE",
    default=Mode.READ,
    audit_sink=audit_sink,
)
"""RBAC gate. Default-deny posture: PANOS_MODE unset = read-only access."""

# Always-on operating context for any agent using this server. Kept tight — it
# is injected into every session's context by the client. States the invariants
# that separate a firewall target from a Panorama one, because getting that wrong
# silently produces confidently-empty results (see the guard/scope tools).
SERVER_INSTRUCTIONS = """\
PAN-OS / Panorama tool semantics — read before interpreting results.

Target type first. Call get_firewall_info: model "Panorama" or "M-*" means a
Panorama; otherwise a firewall. Behavior differs sharply between them.

On a Panorama, firewall-scoped tools guard instead of returning misleading data:
- Config reads (summarize_security_policy, get_security_rules, get_decryption_rules,
  count_rules_by_action, find_rule_by_name, …) return a REDIRECT error naming the
  correct panorama_* sibling — re-issue against it, per device group.
- Dataplane/runtime reads (get_routing_table, get_interfaces, get_arp_table,
  get_ipsec_tunnels, get_userid_mappings, rule hit counts, …) return a REJECT
  error — Panorama has no data plane; target a managed firewall via firewall=<name>
  (list_firewalls / panorama_get_managed_devices to find one).
Never report "nothing configured" on a guard error — follow the redirect.

Scope/template tags: scope-aware readers (objects, profiles) tag each item with
scope (shared or a device-group); template-aware readers (zones, routes, vlans)
tag each with template. An empty "shared" scope is normal — real config commonly
lives in device groups and templates. ALWAYS check the timed_out field: a partial
walk is not an empty configuration.

Read-only by default (PANOS_MODE=read). Writes go to candidate config and require
a higher mode plus an explicit commit — never assume a change is live.

Token discipline: prefer summary/count tools (summarize_security_policy,
count_objects_by_type, panorama_count_rules_per_device_group) before full dumps;
narrow list reads with pattern=, fields=, and pagination.
"""

mcp = FastMCP("panos-mcp", instructions=SERVER_INSTRUCTIONS)

ctx = ToolContext(mcp=mcp, gate=gate, tls=tls_config, audit_sink=audit_sink)
"""Shared context every register_*_tools function consumes."""

# Diagnostic tools (always available — both require READ).
register_status_tools(ctx, audit_sink=audit_sink)
register_firewall_tools(ctx)

# Phase 3 read tools.
register_system_tools(ctx)
register_diagnostics_tools(ctx)
register_network_tools(ctx)
register_security_tools(ctx)
register_objects_tools(ctx)
register_nat_tools(ctx)
register_userid_tools(ctx)
register_admin_tools(ctx)
register_vpn_tools(ctx)
register_panorama_tools(ctx)
register_logs_tools(ctx)
register_threat_tools(ctx)
register_certificates_tools(ctx)
register_licenses_tools(ctx)
register_utility_tools(ctx)
register_admin_ops_tools(ctx)
register_aggregation_tools(ctx)


def main() -> None:
    """Entry point for the ``panos-mcp`` console script."""
    load_firewall_config()
    print(f"panos-mcp {__version__} starting", file=sys.stderr)
    print(f"PanOS TLS:   {describe_tls(tls_config)}", file=sys.stderr)
    print(f"PanOS RBAC:  {gate.describe()}", file=sys.stderr)
    print(f"PanOS audit: {audit_sink.describe()}", file=sys.stderr)
    serial_state = "ON" if serial_connection_enabled() else "OFF"
    print(
        f"PanOS serial: allow_serial_connection={serial_state} "
        "(serial-through-Panorama; direct entries always take precedence)",
        file=sys.stderr,
    )
    mcp.run()


if __name__ == "__main__":
    main()
