"""``server_status`` — diagnostic tool reporting the active server posture.

Always available (registered under ``Mode.READ``). Returns active RBAC
mode, capability flags, tool counts, TLS verification posture, audit
destination, and the configured firewall registry.
"""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import AuditSink, Mode, describe_tls

from ..config.firewalls import is_multi_firewall, list_firewall_entries
from ._common import ToolContext


def register_status_tools(ctx: ToolContext, *, audit_sink: AuditSink) -> None:
    """Register the ``server_status`` tool against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def server_status() -> dict[str, Any]:
        """Report the panos-mcp server's current posture.

        Returns the active RBAC mode, capability flags, tool counts, TLS
        verification state, audit destination, and the configured firewall
        registry. Useful for confirming deployment configuration without
        reading server logs.
        """
        summary = ctx.gate.summary()
        return {
            "mode": summary["mode"],
            "tools_total": summary["tools_total"],
            "tools_enabled": summary["tools_enabled"],
            "tools_blocked": summary["tools_blocked"],
            "blocked_tools": summary["blocked_tools"],
            "capabilities": {
                "read": True,
                "write_objects": ctx.gate.allows(Mode.STANDARD),
                "write_rules": ctx.gate.allows(Mode.FULL),
                "commit_and_raw_api": ctx.gate.allows(Mode.ADMIN),
            },
            "tls": describe_tls(ctx.tls),
            "audit": audit_sink.describe(),
            "firewalls": {
                "configured": list_firewall_entries(),
                "multi_firewall": is_multi_firewall(),
            },
        }


__all__ = ["register_status_tools"]
