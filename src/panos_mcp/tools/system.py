"""System-level read tools: firewall info, HA status, sessions, resources.

All four are op-command wrappers — they call ``client.op(...)``, unwrap the
``<result>`` element to a dict, and apply :func:`shape_single` for a lean
view.
"""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, VerboseFlag

from ..responses.schemas import (
    SHAPE_ACTIVE_SESSIONS,
    SHAPE_FIREWALL_INFO,
    SHAPE_HA_STATUS,
    SHAPE_SYSTEM_RESOURCES,
)
from ..responses.shapers import shape_single
from ._common import ToolContext, op_to_dict


def register_system_tools(ctx: ToolContext) -> None:
    """Register the four system-level read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_firewall_info(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Hostname, model, serial, software version, uptime.

        Default response includes the fields most operators care about.
        Set verbose=true for licensing, signatures, and platform details.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><system><info></info></system></show>")
        system = result.get("system", result)
        return shape_single(system, shape=SHAPE_FIREWALL_INFO, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_ha_status(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """High-availability state and peer information."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client,
            "<show><high-availability><state></state></high-availability></show>",
        )
        return shape_single(result, shape=SHAPE_HA_STATUS, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_active_sessions(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Active session count and summary statistics."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><session><info></info></session></show>")
        return shape_single(result, shape=SHAPE_ACTIVE_SESSIONS, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_system_resources(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """CPU, memory, and disk utilization."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><system><resources></resources></system></show>")
        return shape_single(result, shape=SHAPE_SYSTEM_RESOURCES, verbose=verbose, fields=fields)


__all__ = ["register_system_tools"]
