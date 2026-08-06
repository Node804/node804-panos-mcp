"""Network read tools: interfaces, zones, routes, ARP, VLANs, DHCP, DNS, static routes.

Mix of op-command wrappers (interfaces, ARP, routing-table, DHCP) and
config-tree reads (zones, VLANs, DNS proxy, static routes).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.device import Vsys
from panos.errors import PanDeviceError
from panos.network import (
    StaticRoute,
    VirtualRouter,
    Vlan,
    Zone,
)
from panos.panorama import Panorama, Template
from pydantic import Field

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
from ._common import (
    ToolContext,
    gather_template_config,
    gather_template_objects,
    op_to_dict,
    panos_object_dicts,
    read_timeout,
    reject_panorama_target,
    run_blocking_timeout,
    wrap_panos_error,
    write_success,
)
from ._schemas import MemberValue, PanosName

NextHopType = Literal["ip-address", "next-vr", "none"]


def _items_from_op_table(
    result: dict[str, Any], collection_key: str, item_key: str
) -> list[dict[str, Any]]:
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
        guard = reject_panorama_target(client, "get_interfaces")
        if guard is not None:
            return guard
        result = op_to_dict(client, "<show><interface>all</interface></show>")
        items = _items_from_op_table(result, "hw", "entry") + _items_from_op_table(
            result, "ifnet", "entry"
        )
        return apply_shape(
            items,
            shape=SHAPE_INTERFACE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_zones(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Security zones.

        Template-aware: on a firewall this reads the local zones; on a Panorama
        zones live in templates, so it walks every template (reading vsys1) and
        tags each zone with its source ``template``. A template whose read
        times out is skipped and listed in ``timed_out``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client

        def _refresh_zones(parent: Any) -> Any:
            if isinstance(parent, Template):
                vsys = Vsys("vsys1")
                parent.add(vsys)
                return Zone.refreshall(vsys)
            return Zone.refreshall(parent)

        rows, timed_out = await gather_template_objects(
            client, _refresh_zones, timeout=read_timeout()
        )
        out = apply_shape(
            rows,
            shape=SHAPE_ZONE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out

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
        guard = reject_panorama_target(client, "get_routing_table")
        if guard is not None:
            return guard
        result = op_to_dict(client, "<show><routing><route></route></routing></show>")
        items = _items_from_op_table(result, "flags", "entry") + _items_from_op_table(
            result, "entry", ""
        )
        # Some versions return ``{entry: [...]}`` directly; handle that too.
        if not items and isinstance(result.get("entry"), list):
            items = result["entry"]
        return apply_shape(
            items,
            shape=SHAPE_ROUTE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
        guard = reject_panorama_target(client, "get_arp_table")
        if guard is not None:
            return guard
        result = op_to_dict(client, "<show><arp><entry>all</entry></arp></show>")
        items = _items_from_op_table(result, "entries", "entry")
        return apply_shape(
            items,
            shape=SHAPE_ARP,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_vlans(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """VLAN configuration.

        Template-aware: reads local VLANs on a firewall; on a Panorama walks
        every template and tags each VLAN with its source ``template``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rows, timed_out = await gather_template_objects(
            client, Vlan.refreshall, timeout=read_timeout()
        )
        out = apply_shape(
            rows,
            shape=SHAPE_VLAN,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out

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
        guard = reject_panorama_target(client, "get_dhcp_leases")
        if guard is not None:
            return guard
        result = op_to_dict(client, "<show><dhcp><server><lease>all</lease></server></dhcp></show>")
        items = _items_from_op_table(result, "entry", "")
        if not items and isinstance(result.get("entry"), list):
            items = result["entry"]
        return apply_shape(
            items,
            shape=SHAPE_DHCP_LEASE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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

        DNS proxy isn't modeled in pan-os-python — read via xpath. Template-aware:
        local on a firewall; on a Panorama it walks every template's DNS-proxy
        config, tagging each entry with its source ``template``. Entries promote
        the ``@_name`` attribute to ``name``; a template that times out is listed
        in ``timed_out``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        results, timed_out = await gather_template_config(
            client, "network/dns-proxy", timeout=read_timeout()
        )
        items: list[dict[str, Any]] = []
        for source, result in results:
            section = result.get("dns-proxy", result) if isinstance(result, dict) else {}
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
            shape=SHAPE_DNS_PROXY,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_static_routes(
        firewall: str | None = None,
        virtual_router: str = "default",
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Static routes for a virtual router (defaults to 'default').

        Template-aware: on a firewall this reads the named VR's routes (and
        errors if that VR doesn't exist). On a Panorama, virtual routers live in
        templates, so it walks every template, reads the named VR where present,
        and tags each route with its source ``template`` (templates without that
        VR contribute nothing). A template whose read times out is listed in
        ``timed_out``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client

        timeout_s = read_timeout()

        def _refresh_routes(parent: Any) -> Any:
            vrs = VirtualRouter.refreshall(parent)
            target = next((v for v in vrs if v.name == virtual_router), None)
            if target is None:
                return []
            return StaticRoute.refreshall(target)

        if isinstance(client, Panorama):
            rows, timed_out = await gather_template_objects(
                client, _refresh_routes, timeout=timeout_s
            )
            out = apply_shape(
                rows,
                shape=SHAPE_STATIC_ROUTE,
                verbose=verbose,
                fields=fields,
                pagination=pagination,
                pattern=pattern,
            )
            if timed_out:
                out["timed_out"] = timed_out
            return out

        # Firewall: preserve the explicit "VR not found" error.
        vrs = await run_blocking_timeout(timeout_s, VirtualRouter.refreshall, client)
        target_vr = next((v for v in vrs if v.name == virtual_router), None)
        if target_vr is None:
            return {
                "error": f"Virtual router '{virtual_router}' not found.",
                "items": [],
                "total": 0,
                "count": 0,
            }
        routes = await run_blocking_timeout(timeout_s, StaticRoute.refreshall, target_vr)
        return apply_shape(
            panos_object_dicts(routes),
            shape=SHAPE_STATIC_ROUTE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    # ── Static route CRUD (Mode.FULL) ───────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_static_route(
        name: PanosName,
        destination: MemberValue,
        nexthop_type: NextHopType,
        nexthop_value: MemberValue | None = None,
        interface: PanosName | None = None,
        metric: Annotated[
            int,
            Field(ge=1, le=65535, description="Route metric. 1-65535, default 10."),
        ] = 10,
        virtual_router: PanosName = "default",
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a static route in a virtual router. Staged in candidate config.

        ``nexthop_type='ip-address'`` requires a ``nexthop_value`` IP; 'next-vr'
        requires the target VR name; 'none' (blackhole) takes no nexthop_value.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        vrs = VirtualRouter.refreshall(client)
        target_vr = next((v for v in vrs if v.name == virtual_router), None)
        if target_vr is None:
            return {
                "success": False,
                "operation": "create",
                "name": name,
                "error": f"Virtual router '{virtual_router}' not found.",
            }
        if nexthop_type in ("ip-address", "next-vr") and not nexthop_value:
            return {
                "success": False,
                "operation": "create",
                "name": name,
                "error": f"nexthop_value is required when nexthop_type is '{nexthop_type}'.",
            }
        kwargs: dict[str, Any] = {
            "name": name,
            "destination": destination,
            "nexthop_type": nexthop_type,
            "interface": interface,
            "metric": metric,
        }
        if nexthop_type != "none":
            kwargs["nexthop"] = nexthop_value
        route = StaticRoute(**{k: v for k, v in kwargs.items() if v is not None})
        target_vr.add(route)
        try:
            route.create()
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name, virtual_router=virtual_router)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_static_route(
        name: PanosName,
        virtual_router: PanosName = "default",
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a static route from a virtual router. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        vrs = VirtualRouter.refreshall(client)
        target_vr = next((v for v in vrs if v.name == virtual_router), None)
        if target_vr is None:
            return {
                "success": False,
                "operation": "delete",
                "name": name,
                "error": f"Virtual router '{virtual_router}' not found.",
            }
        route = StaticRoute(name=name)
        target_vr.add(route)
        try:
            route.delete()
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name, virtual_router=virtual_router)


__all__ = ["register_network_tools"]
