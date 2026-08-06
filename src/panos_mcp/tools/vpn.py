"""VPN read tools: IPSec tunnels, GlobalProtect users, GP config."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag

from ..responses.schemas import SHAPE_GP_CONFIG, SHAPE_GP_USER, SHAPE_IPSEC_TUNNEL
from ..responses.shapers import apply_shape
from ._common import (
    ToolContext,
    gather_template_config,
    op_to_dict,
    read_timeout,
    reject_panorama_target,
)


def register_vpn_tools(ctx: ToolContext) -> None:
    """Register the three VPN read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_ipsec_tunnels(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """IPSec tunnel state and security associations."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = reject_panorama_target(client, "get_ipsec_tunnels")
        if guard is not None:
            return guard
        result = op_to_dict(client, "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>")
        # Response shape: <entries><entry>...</entry></entries> typically.
        entries = result.get("entries", {})
        if isinstance(entries, dict):
            items_raw = entries.get("entry", [])
            items = items_raw if isinstance(items_raw, list) else [items_raw]
        elif isinstance(entries, list):
            items = entries
        else:
            items = []
        return apply_shape(
            [i for i in items if isinstance(i, dict)],
            shape=SHAPE_IPSEC_TUNNEL,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_globalprotect_users(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Currently connected GlobalProtect VPN users."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = reject_panorama_target(client, "get_globalprotect_users")
        if guard is not None:
            return guard
        result = op_to_dict(
            client,
            "<show><global-protect-gateway><current-user></current-user>"
            "</global-protect-gateway></show>",
        )
        entries = result.get("entry", [])
        items: list[dict[str, Any]]
        if isinstance(entries, list):
            items = [e for e in entries if isinstance(e, dict)]
        elif isinstance(entries, dict):
            items = [entries]
        else:
            items = []
        return apply_shape(
            items,
            shape=SHAPE_GP_USER,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_globalprotect_config(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """GlobalProtect gateway and portal configuration.

        GP isn't modeled in pan-os-python — read via xpath. Template-aware:
        local on a firewall; on a Panorama it walks every template's GP config,
        tagging each entry with its source ``template`` and a ``kind``
        (``global-protect-gateway`` / ``global-protect-portal``). A template that
        times out is listed in ``timed_out``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        results, timed_out = await gather_template_config(
            client, "vsys/entry[@name='vsys1']/global-protect", timeout=read_timeout()
        )
        items: list[dict[str, Any]] = []
        for source, result in results:
            gp = result.get("global-protect", result) if isinstance(result, dict) else {}
            if not isinstance(gp, dict):
                continue
            for kind in ("global-protect-gateway", "global-protect-portal"):
                section = gp.get(kind, {})
                if not isinstance(section, dict):
                    continue
                entries = section.get("entry", [])
                if isinstance(entries, dict):
                    entries = [entries]
                for e in entries:
                    if not isinstance(e, dict):
                        continue
                    row = dict(e)
                    if "name" not in row and "@_name" in row:
                        row["name"] = row["@_name"]
                    row["kind"] = kind
                    if source is not None:
                        row["template"] = source
                    items.append(row)
        out = apply_shape(
            items,
            shape=SHAPE_GP_CONFIG,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out


__all__ = ["register_vpn_tools"]
