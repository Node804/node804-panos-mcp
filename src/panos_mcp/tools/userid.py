"""User-ID read tools: IP-user mappings, groups, agent config."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag

from ..responses.schemas import SHAPE_USERID_AGENT, SHAPE_USERID_GROUP, SHAPE_USERID_MAPPING
from ..responses.shapers import apply_shape
from ._common import (
    ToolContext,
    gather_template_config,
    op_to_dict,
    read_timeout,
    reject_panorama_target,
)


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
        guard = reject_panorama_target(client, "get_userid_mappings")
        if guard is not None:
            return guard
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
        guard = reject_panorama_target(client, "get_userid_groups")
        if guard is not None:
            return guard
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
        """User-ID agent configuration.

        ``UserIdAgent`` isn't modeled in this pan-os-python version, so this
        reads the config via xpath. Template-aware: local on a firewall; on a
        Panorama it walks every template's User-ID agent config, tagging each
        entry with its source ``template``. A template that times out is listed
        in ``timed_out``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        results, timed_out = await gather_template_config(
            client, "vsys/entry[@name='vsys1']/user-id-agent", timeout=read_timeout()
        )
        items: list[dict[str, Any]] = []
        for source, result in results:
            section = result.get("user-id-agent", result) if isinstance(result, dict) else {}
            if not isinstance(section, dict) or "entry" not in section:
                continue
            raw = section["entry"]
            for e in raw if isinstance(raw, list) else [raw]:
                if not isinstance(e, dict):
                    continue
                row = dict(e)
                if "name" not in row and "@_name" in row:
                    row["name"] = row["@_name"]
                if source is not None:
                    row["template"] = source
                items.append(row)
        out = apply_shape(
            items,
            shape=SHAPE_USERID_AGENT,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out


__all__ = ["register_userid_tools"]
