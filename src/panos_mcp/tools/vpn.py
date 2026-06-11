"""VPN read tools: IPSec tunnels, GlobalProtect users, GP config."""

from __future__ import annotations

from typing import Any

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag

from ..responses.schemas import SHAPE_GP_CONFIG, SHAPE_GP_USER, SHAPE_IPSEC_TUNNEL
from ..responses.shapers import apply_shape
from ._common import ToolContext, build_running_config_xpath_cmd, op_to_dict


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
        """GlobalProtect gateway and portal configuration."""
        # GP isn't fully modeled in pan-os-python; use op-style xpath read.
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
            "/global-protect"
        )
        result = op_to_dict(client, build_running_config_xpath_cmd(xpath))
        gp = result.get("global-protect", result) if isinstance(result, dict) else result
        if not isinstance(gp, dict):
            return {"total": 0, "count": 0, "items": []}
        # Flatten gateway + portal entries into one list with a 'kind' field.
        items: list[dict[str, Any]] = []
        for kind in ("global-protect-gateway", "global-protect-portal"):
            section = gp.get(kind, {})
            if not isinstance(section, dict):
                continue
            entries = section.get("entry", [])
            if isinstance(entries, dict):
                entries = [entries]
            for e in entries:
                if isinstance(e, dict):
                    e2 = dict(e)
                    e2["kind"] = kind
                    items.append(e2)
        return apply_shape(
            items,
            shape=SHAPE_GP_CONFIG,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )


__all__ = ["register_vpn_tools"]
