"""License read tools: license inventory + usage details."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag

from ..responses.schemas import SHAPE_LICENSE, SHAPE_LICENSE_USAGE
from ..responses.shapers import apply_shape, shape_single
from ._common import ToolContext, op_to_dict


def _license_entries(result: Any) -> list[dict[str, Any]]:
    """Extract license entries from a 'request license info' op response."""
    if not isinstance(result, dict):
        return []
    licenses = result.get("licenses", {})
    entry = licenses.get("entry", []) if isinstance(licenses, dict) else []
    if isinstance(entry, dict):
        return [entry]
    if isinstance(entry, list):
        return [e for e in entry if isinstance(e, dict)]
    return []


def register_licenses_tools(ctx: ToolContext) -> None:
    """Register the two license read tools."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_licenses(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Installed licenses with feature and expiry.

        The activation ``authcode`` is a reusable credential and is omitted
        from the default response; pass ``verbose=true`` or
        ``fields=["authcode"]`` to include it.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<request><license><info></info></license></request>")
        items = _license_entries(result)
        return apply_shape(
            items,
            shape=SHAPE_LICENSE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_license_usage(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """VM license usage details (model, serial, capacity tier, mode)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><system><info></info></system></show>")
        system = result.get("system", result) if isinstance(result, dict) else result
        return shape_single(system, shape=SHAPE_LICENSE_USAGE, verbose=verbose, fields=fields)


__all__ = ["register_licenses_tools"]
