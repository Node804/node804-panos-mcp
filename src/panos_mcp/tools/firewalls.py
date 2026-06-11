"""``list_firewalls`` — enumerate configured firewall targets (no api_keys)."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import Mode

from ..config.firewalls import is_multi_firewall, list_firewall_entries
from ._common import ToolContext


def register_firewall_tools(ctx: ToolContext) -> None:
    """Register ``list_firewalls`` against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def list_firewalls() -> dict[str, Any]:
        """List configured firewall target names + hosts.

        Returns the registry contents (no API keys ever). The
        ``firewall_param_required`` flag indicates whether the caller must
        pass a ``firewall`` argument to other tools — true when multiple
        targets are configured (no default to pick safely), false when a
        single target makes the choice unambiguous.
        """
        entries = list_firewall_entries()
        multi = is_multi_firewall()

        if not entries:
            mode = "environment"
        elif len(entries) == 1:
            mode = "single"
        else:
            mode = "multi"

        return {
            "mode": mode,
            "firewall_param_required": multi,
            "firewalls": entries,
        }


__all__ = ["register_firewall_tools"]
