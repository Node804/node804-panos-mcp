"""Threat / content read tools: WildFire, AV signatures, content versions, URL categories."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.panorama import Panorama

from ..responses.schemas import (
    SHAPE_AV_VERSION,
    SHAPE_CONTENT_VERSIONS,
    SHAPE_URL_CATEGORY,
    SHAPE_WILDFIRE,
)
from ..responses.shapers import apply_shape, shape_single
from ._common import ToolContext, op_to_dict


def _entries(result: Any, *keys: str) -> list[dict[str, Any]]:
    cursor: Any = result
    for k in keys:
        if not isinstance(cursor, dict):
            return []
        cursor = cursor.get(k, {})
    if isinstance(cursor, list):
        return [c for c in cursor if isinstance(c, dict)]
    if isinstance(cursor, dict):
        return [cursor]
    return []


def register_threat_tools(ctx: ToolContext) -> None:
    """Register the four threat/content read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_wildfire_status(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """WildFire cloud connection status and statistics."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        if isinstance(client, Panorama):
            return {
                "error": (
                    "'get_wildfire_status' reads the per-firewall WildFire cloud "
                    "connection, which a Panorama appliance does not maintain. Target "
                    "a managed firewall with the 'firewall' parameter (use "
                    "list_firewalls or panorama_get_managed_devices to find one)."
                )
            }
        result = op_to_dict(client, "<show><wildfire><status></status></wildfire></show>")
        return shape_single(result, shape=SHAPE_WILDFIRE, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_antivirus_version(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Active AV / threat / WildFire signature versions."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><system><info></info></system></show>")
        system = result.get("system", result) if isinstance(result, dict) else result
        return shape_single(system, shape=SHAPE_AV_VERSION, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_content_versions(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Available content update versions."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client,
            "<request><content><upgrade><info></info></upgrade></content></request>",
        )
        items = _entries(result, "content-updates", "entry") or _entries(result, "entry")
        return apply_shape(
            items,
            shape=SHAPE_CONTENT_VERSIONS,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_url_categories(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Predefined URL filtering categories.

        This list is large (>200 categories) and rarely changes; consider
        caching the response client-side. Default pagination caps at 100.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # Read from predefined config tree.
        result = op_to_dict(
            client,
            "<show><config><running><xpath>"
            "/config/predefined/pan-url-categories"
            "</xpath></running></config></show>",
        )
        items = _entries(result, "pan-url-categories", "entry") or _entries(result, "entry")
        return apply_shape(
            items,
            shape=SHAPE_URL_CATEGORY,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )


__all__ = ["register_threat_tools"]
