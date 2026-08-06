"""``list_firewalls`` — enumerate configured firewall targets (no api_keys)."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import Mode

from ..client import discover_managed_devices
from ..config.firewalls import (
    is_multi_firewall,
    list_firewall_entries,
    serial_connection_enabled,
)
from ._common import ToolContext, run_blocking


def register_firewall_tools(ctx: ToolContext) -> None:
    """Register ``list_firewalls`` against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def list_firewalls() -> dict[str, Any]:
        """List firewall targets: configured entries plus (when enabled) the
        live Panorama-managed fleet reachable by serial redirect.

        Returns the registry contents (no API keys ever). The
        ``firewall_param_required`` flag indicates whether the caller must
        pass a ``firewall`` argument to other tools — true when multiple
        targets are configured (no default to pick safely), false when a
        single target makes the choice unambiguous.

        When ``PANOS_ALLOW_SERIAL_CONNECTION`` is enabled and a Panorama is
        reachable, ``managed_devices`` lists every device Panorama manages;
        pass one's ``name`` (hostname) or ``serial`` as the ``firewall``
        argument to any tool to reach it through Panorama — no per-device key
        required. Configured (direct) entries always take precedence over a
        managed device of the same name.
        """
        entries = list_firewall_entries()
        multi = is_multi_firewall()

        if not entries:
            mode = "environment"
        elif len(entries) == 1:
            mode = "single"
        else:
            mode = "multi"

        result: dict[str, Any] = {
            "mode": mode,
            "firewall_param_required": multi,
            "serial_connection": serial_connection_enabled(),
            "firewalls": entries,
        }

        if serial_connection_enabled():
            # Network call — offload so the event loop stays responsive, and
            # never let a Panorama hiccup fail the whole listing.
            try:
                managed = await run_blocking(discover_managed_devices, tls=ctx.tls)
            except Exception:
                managed = []
            configured_names = {e.get("name") for e in entries}
            result["managed_devices"] = [
                d for d in managed if d.get("name") not in configured_names
            ]

        return result


__all__ = ["register_firewall_tools"]
