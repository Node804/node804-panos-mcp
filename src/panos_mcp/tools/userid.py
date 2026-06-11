"""User-ID read tools: IP-user mappings, groups, agent config."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag

from ..responses.schemas import SHAPE_USERID_AGENT, SHAPE_USERID_GROUP, SHAPE_USERID_MAPPING
from ..responses.shapers import apply_shape
from ._common import ToolContext, op_to_dict


def _entries_under(result: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    """Walk ``result[key1][key2]...`` defensively and return a list of entries."""
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


def register_userid_tools(ctx: ToolContext) -> None:
    """Register the three User-ID read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_userid_mappings(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """IP-to-user mappings learned by User-ID."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client,
            "<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>",
        )
        items = _entries_under(result, "entry") or _entries_under(result, "entries", "entry")
        return apply_shape(
            items,
            shape=SHAPE_USERID_MAPPING,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_userid_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """User groups known via User-ID."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><user><group><list></list></group></user></show>")
        items = _entries_under(result, "entry") or _entries_under(result, "groups", "entry")
        return apply_shape(
            items,
            shape=SHAPE_USERID_GROUP,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_userid_config(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """User-ID agent configuration."""
        try:
            from panos.device import UserIdAgent
        except ImportError:
            return {
                "error": "UserIdAgent not modeled in this pan-os-python version.",
                "items": [],
                "total": 0,
                "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        agents = UserIdAgent.refreshall(client)
        from ._common import panos_object_dicts

        return apply_shape(
            panos_object_dicts(agents),
            shape=SHAPE_USERID_AGENT,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )


__all__ = ["register_userid_tools"]
