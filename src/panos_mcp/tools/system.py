"""System-level read tools: firewall info, HA status, sessions, resources.

All four are op-command wrappers — they call ``client.op(...)``, unwrap the
``<result>`` element to a dict, and apply :func:`shape_single` for a lean
view.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_toolkit import FieldsList, Mode, VerboseFlag
from panos.panorama import Panorama

from ..responses.schemas import (
    SHAPE_ACTIVE_SESSIONS,
    SHAPE_FIREWALL_INFO,
    SHAPE_HA_STATUS,
    SHAPE_SYSTEM_RESOURCES,
)
from ..responses.shapers import shape_single
from ._common import ToolContext, op_to_dict


def _parse_top_output(result: dict[str, Any]) -> dict[str, Any]:
    """Extract structured metrics from ``top`` text returned by ``show system resources``.

    The ``<result>`` element contains raw ``top`` output as text.  We pull
    out load averages, CPU percentages, and memory figures so the shaping
    pipeline has real keys to filter on.
    """
    text = result.get("#text", "") if isinstance(result, dict) else ""
    if not text:
        return result  # already structured or empty — pass through

    parsed: dict[str, Any] = {}

    # load average: 0.14, 0.17, 0.14
    m = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", text)
    if m:
        parsed["load-average"] = {
            "1min": m.group(1),
            "5min": m.group(2),
            "15min": m.group(3),
        }

    # %Cpu(s):  3.2 us,  2.1 sy,  0.0 ni, 94.5 id, ...
    m = re.search(r"%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy,\s*[\d.]+\s*ni,\s*([\d.]+)\s*id", text)
    if m:
        user = float(m.group(1))
        system = float(m.group(2))
        idle = float(m.group(3))
        parsed["cpu"] = {
            "user": f"{user}%",
            "system": f"{system}%",
            "idle": f"{idle}%",
            "used": f"{round(user + system, 1)}%",
        }

    # KiB Mem:   8061048 total,  7643264 used,   417784 free, ...
    # — or —  MiB Mem :   3920.3 total,   1234.5 free,   2345.6 used, ...
    m = re.search(
        r"[KMG]iB Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*(?:free|used),\s*([\d.]+)\s*(?:used|free)",
        text,
    )
    if m:
        parsed["memory"] = {
            "total": m.group(1),
            "values": [m.group(2), m.group(3)],
        }
    # Simpler fallback: just capture the whole Mem line
    if "memory" not in parsed:
        m = re.search(r"[KMG]iB Mem[^\n]+", text)
        if m:
            parsed["memory"] = m.group(0).strip()

    # Swap line (bonus for verbose)
    m = re.search(r"[KMG]iB Swap[^\n]+", text)
    if m:
        parsed["swap"] = m.group(0).strip()

    # Uptime fragment  "up 5 days,  3:15"
    m = re.search(r"up\s+(.+?),\s+\d+\s+user", text)
    if m:
        parsed["uptime"] = m.group(1).strip()

    # If nothing parsed, return raw text so caller still gets something
    if not parsed:
        parsed["raw"] = text

    return parsed


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
        """Active session count and summary statistics.

        This is a per-firewall command. When the resolved target is a
        Panorama appliance, pass the ``firewall`` parameter to specify
        which managed device to query.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        if isinstance(client, Panorama):
            return {
                "error": (
                    "'show session info' is a per-firewall command and cannot "
                    "run against Panorama directly. Specify a firewall target "
                    "with the 'firewall' parameter (use list_firewalls to see "
                    "available targets)."
                )
            }
        result = op_to_dict(client, "<show><session><info></info></session></show>")
        return shape_single(result, shape=SHAPE_ACTIVE_SESSIONS, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_system_resources(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """CPU, memory, and disk utilization.

        ``show system resources`` returns raw ``top`` text.  This tool
        parses it into structured fields so the shaping pipeline can
        filter them normally.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><system><resources></resources></system></show>")
        parsed = _parse_top_output(result)
        return shape_single(parsed, shape=SHAPE_SYSTEM_RESOURCES, verbose=verbose, fields=fields)


__all__ = ["register_system_tools"]
