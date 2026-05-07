"""Network read tools: interfaces, zones, routes, ARP, VLANs, DHCP, DNS, static routes.

Mix of op-command wrappers (interfaces, ARP, routing-table, DHCP) and
config-tree reads (zones, VLANs, DNS proxy, static routes).
"""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.network import (
    StaticRoute,
    VirtualRouter,
    Vlan,
    Zone,
)

from ..responses.schemas import (
    SHAPE_ARP,
    SHAPE_DHCP_LEASE,
    SHAPE_DNS_PROXY,
    SHAPE_INTERFACE,
    SHAPE_ROUTE,
    SHAPE_STATIC_ROUTE,
    SHAPE_VLAN,
    SHAPE_ZONE,
)
from ..responses.shapers import apply_shape
from ._common import ToolContext, op_to_dict, panos_object_dicts


def _items_from_op_table(result: dict[str, Any], collection_key: str, item_key: str) -> list[dict[str, Any]]:
    """Extract a list from a typical PAN-OS op response shape.

    Many op commands return ``<result><collection><entry>...</entry>...</collection></result>``
    which our converter renders as ``{collection_key: {item_key: [...]}}`` or
    ``{collection_key: {item_key: {...}}}`` for a single item. This helper
    normalizes to a list either way.
    """
    collection = result.get(collection_key, {})
    if not isinstance(collection, dict):
        return []
    items = collection.get(item_key, [])
    if isinstance(items, list):
        return [i for i in items if isinstance(i, dict)]
    if isinstance(items, dict):
        return [items]
    return []


def register_network_tools(ctx: ToolContext) -> None:
    """Register the eight network read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_interfaces(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """All network interfaces with status, IP, and zone."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><interface>all</interface></show>")
        items = _items_from_op_table(result, "hw", "entry") + _items_from_op_table(
            result, "ifnet", "entry"
        )
        return apply_shape(
            items, shape=SHAPE_INTERFACE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_zones(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Security zones configured on the firewall."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        zones = Zone.refreshall(client)
        return apply_shape(
            panos_object_dicts(zones), shape=SHAPE_ZONE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_routing_table(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Active routing table entries."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><routing><route></route></routing></show>")
        items = _items_from_op_table(result, "flags", "entry") + _items_from_op_table(
            result, "entry", ""
        )
        # Some versions return ``{entry: [...]}`` directly; handle that too.
        if not items and isinstance(result.get("entry"), list):
            items = result["entry"]
        return apply_shape(
            items, shape=SHAPE_ROUTE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_arp_table(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """ARP entries learned by the firewall."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><arp><entry>all</entry></arp></show>")
        items = _items_from_op_table(result, "entries", "entry")
        return apply_shape(
            items, shape=SHAPE_ARP, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_vlans(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """VLAN configuration."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        vlans = Vlan.refreshall(client)
        return apply_shape(
            panos_object_dicts(vlans), shape=SHAPE_VLAN,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_dhcp_leases(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """DHCP server lease assignments."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client, "<show><dhcp><server><lease>all</lease></server></dhcp></show>"
        )
        items = _items_from_op_table(result, "entry", "")
        if not items and isinstance(result.get("entry"), list):
            items = result["entry"]
        return apply_shape(
            items, shape=SHAPE_DHCP_LEASE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_dns_proxy(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """DNS proxy configuration.

        DNS proxy isn't modeled directly in pan-os-python — we read it via
        an op-style xpath show, which returns the raw config subtree.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/dns-proxy"
        result = op_to_dict(
            client, f"<show><config><running><xpath>{xpath}</xpath></running></config></show>"
        )
        proxies_section = result.get("dns-proxy", result) if isinstance(result, dict) else {}
        if isinstance(proxies_section, dict) and "entry" in proxies_section:
            entries_raw = proxies_section["entry"]
            items = entries_raw if isinstance(entries_raw, list) else [entries_raw]
        else:
            items = []
        return apply_shape(
            [i for i in items if isinstance(i, dict)],
            shape=SHAPE_DNS_PROXY, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_static_routes(
        firewall: str | None = None,
        virtual_router: str = "default",
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Static routes for a virtual router (defaults to 'default')."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # Find the named virtual router and refresh its static routes.
        vrs = VirtualRouter.refreshall(client)
        target_vr = next((v for v in vrs if v.name == virtual_router), None)
        if target_vr is None:
            return {"error": f"Virtual router '{virtual_router}' not found.", "items": [], "total": 0, "count": 0}
        routes = StaticRoute.refreshall(target_vr)
        return apply_shape(
            panos_object_dicts(routes), shape=SHAPE_STATIC_ROUTE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )


__all__ = ["register_network_tools"]
