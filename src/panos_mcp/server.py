"""FastMCP server entrypoint for panos-mcp.

Phase 3: full read-only tool surface plus the always-on diagnostic tools.
71 read tools across system / network / security / objects / NAT / user-id /
admin / VPN / Panorama / logs / threat / certificates / licenses / utility,
each with default-lean responses (verbose=true to opt out) and pagination /
pattern filtering.

Environment variables:

| Var                       | Purpose                                                |
|---------------------------|--------------------------------------------------------|
| ``PANOS_MODE``            | RBAC mode (read/standard/full/admin). Default: read.   |
| ``PANOS_AUDIT_LOG``       | Path to JSON-lines audit log. Unset = audit disabled.  |
| ``PANOS_TLS_VERIFY``      | true (default) / false / 1 / 0 / yes / no.             |
| ``PANOS_TLS_CA``          | Optional path to a custom CA PEM bundle.               |
| ``PANOS_FIREWALLS_CONFIG``| Override path for firewalls.json.                      |
| ``PANOS_HOST``            | Single-firewall fallback hostname.                     |
| ``PANOS_API_KEY``         | Single-firewall fallback API key.                      |
"""

from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP
from mcp_toolkit import Mode, ModeGate, describe_tls, open_sink, resolve_tls_config

from . import __version__
from .config.firewalls import load_firewall_config
from .tools._common import ToolContext
from .tools.admin import register_admin_tools
from .tools.admin_ops import register_admin_ops_tools
from .tools.certificates import register_certificates_tools
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

mcp = FastMCP("panos-mcp")

ctx = ToolContext(mcp=mcp, gate=gate, tls=tls_config)
"""Shared context every register_*_tools function consumes."""

# Diagnostic tools (always available — both require READ).
register_status_tools(ctx, audit_sink=audit_sink)
register_firewall_tools(ctx)

# Phase 3 read tools.
register_system_tools(ctx)
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


def main() -> None:
    """Entry point for the ``panos-mcp`` console script."""
    load_firewall_config()
    print(f"panos-mcp {__version__} starting", file=sys.stderr)
    print(f"PanOS TLS:   {describe_tls(tls_config)}", file=sys.stderr)
    print(f"PanOS RBAC:  {gate.describe()}", file=sys.stderr)
    print(f"PanOS audit: {audit_sink.describe()}", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
