"""Network read tools: interfaces, zones, routes, ARP, VLANs, DHCP, DNS, static routes.

Mix of op-command wrappers (interfaces, ARP, routing-table, DHCP) and
config-tree reads (zones, VLANs, DNS proxy, static routes).
"""

from __future__ import annotations

import contextlib
import json
from typing import Annotated, Any, Literal

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.device import Vsys
from panos.errors import PanDeviceError
from panos.network import (
    LogicalRouter,
    StaticRoute,
    VirtualRouter,
    Vlan,
    Vrf,
    VrfStaticRoute,
    VrfStaticRouteV6,
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
    ROUTING_ENGINE_ADVANCED,
    ROUTING_ENGINE_LEGACY,
    ROUTING_ENGINE_UNKNOWN,
    ToolContext,
    detect_routing_engine,
    gather_template_config,
    gather_template_objects,
    op_to_dict,
    panos_object_dicts,
    read_timeout,
    reject_are_vr_write,
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


# ── Advanced Routing Engine route parsing ───────────────────────────────────
# ARE is FRRouting under the hood, and it shows: unlike every other PAN-OS op
# command, ``show advanced-routing route`` does not return XML rows. It returns
# a single ``<json>`` element whose text is FRR's native JSON, keyed by logical
# router and then by prefix, with an array of routes per prefix and an array of
# nexthops per route:
#
#   {"public-lr": {"0.0.0.0/0": [{"prefix": ..., "protocol": "static",
#                                 "metric": 10, "nexthops": [{...}, {...}]}]}}
#
# ``element_to_dict`` renders the ``<json>`` leaf as a plain string, so the
# payload arrives as ``result["json"]`` ready for ``json.loads``.

ARE_ROUTE_CMD = "<show><advanced-routing><route></route></advanced-routing></show>"

# FRR reports a directly-connected route with no nexthop address at all. Legacy
# PAN-OS prints ``0.0.0.0`` in that slot. Emitting an explicit token keeps the
# field present on every row — a missing key would be stripped by the shaper's
# drop-None pass and make the list schema-inconsistent, which is exactly the
# ambiguity ``_coerce_disabled`` exists to avoid elsewhere in this codebase.
ARE_CONNECTED_NEXTHOP = "connected"


def _iter_are_prefix_maps(
    payload: dict[str, Any],
) -> list[tuple[str | None, dict[str, Any]]]:
    """Normalize the top level of the ARE payload to ``(logical_router, prefixes)``.

    The documented shape is keyed by logical router. A single-logical-router
    device can instead return FRR's bare prefix map, so accept both rather than
    silently yielding nothing on the simpler layout.
    """
    lr_scoped: list[tuple[str | None, dict[str, Any]]] = []
    bare: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            lr_scoped.append((key, value))
        elif isinstance(value, list):
            bare[key] = value
    if bare:
        lr_scoped.append((None, bare))
    return lr_scoped


def _are_route_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten the ARE JSON payload into one row per (prefix, nexthop).

    Fanning out per nexthop mirrors how the legacy route table represents ECMP
    — one row per path — so the two engines produce comparable output and a
    multi-path route can't collapse into a single row that hides half its
    nexthops.
    """
    rows: list[dict[str, Any]] = []
    for lr_name, prefixes in _iter_are_prefix_maps(payload):
        if not isinstance(prefixes, dict):
            continue
        for prefix, routes in prefixes.items():
            for route in routes if isinstance(routes, list) else [routes]:
                if not isinstance(route, dict):
                    continue
                base = {
                    "destination": route.get("prefix", prefix),
                    "metric": route.get("metric"),
                    "age": route.get("uptime"),
                    "protocol": route.get("protocol"),
                    "vrf": route.get("vrfName"),
                    "logical_router": lr_name,
                    "distance": route.get("distance"),
                    "selected": route.get("selected"),
                    "installed": route.get("installed"),
                }
                nexthops = route.get("nexthops")
                if not isinstance(nexthops, list) or not nexthops:
                    rows.append({**base, "nexthop": None, "interface": None})
                    continue
                for nh in nexthops:
                    if not isinstance(nh, dict):
                        continue
                    address = nh.get("ip") or nh.get("ipv6")
                    if address is None and nh.get("directlyConnected"):
                        address = ARE_CONNECTED_NEXTHOP
                    flags = nh.get("flags")
                    rows.append(
                        {
                            **base,
                            "nexthop": address,
                            "interface": nh.get("interfaceName"),
                            # FRR pads its flag string ("A E ") — and note the
                            # alphabet differs from legacy PAN-OS route flags,
                            # so don't write filters that assume either.
                            "flags": flags.strip() if isinstance(flags, str) else flags,
                            "active": nh.get("active"),
                        }
                    )
    return rows


def parse_are_routes(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a ``show advanced-routing route`` response into route rows.

    Raises :class:`ValueError` when the ``<json>`` payload is missing or
    unparseable — the caller turns that into an explicit error rather than an
    empty list, because a silent empty routing table is the exact failure this
    whole code path exists to eliminate.
    """
    raw = result.get("json")
    if raw is None:
        raise ValueError(
            "response contained no <json> element (expected FRR JSON from the "
            "Advanced Routing Engine)"
        )
    if isinstance(raw, dict):  # already-decoded payload (test doubles)
        return _are_route_rows(raw)
    if not isinstance(raw, str):
        raise ValueError(f"expected a JSON string in <json>, got {type(raw).__name__}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not decode the JSON payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object, got {type(payload).__name__}")
    return _are_route_rows(payload)


class _TaggedObject:
    """Wrap a pan-os-python object so extra scope tags ride along in ``.about()``.

    ``gather_template_objects`` calls ``.about()`` itself, so a callback can't
    annotate rows after the fact; wrapping lets the ARE branch attach
    ``vrf`` / ``logical_router`` / ``routing_engine`` inside the walk.
    """

    def __init__(self, obj: Any, **tags: Any) -> None:
        self._obj = obj
        self._tags = tags
        self.name = getattr(obj, "name", None)

    def about(self) -> dict[str, Any]:
        return {**self._obj.about(), **self._tags}


def _are_static_routes(parent: Any, vrf_filter: str | None) -> list[Any]:
    """Collect ARE static routes under ``parent``, tagged with VRF + logical router.

    ``vrf_filter`` selects a single VRF by name when it matches one; when it
    matches nothing the filter is ignored and every VRF is returned. Silently
    returning zero rows because the caller's legacy ``virtual_router`` name
    doesn't exist as a VRF would reproduce the very false negative this
    feature fixes.
    """
    pairs: list[tuple[Any, Any]] = []
    for lr in LogicalRouter.refreshall(parent):
        for vrf in Vrf.refreshall(lr):
            pairs.append((lr, vrf))

    if vrf_filter is not None and any(vrf.name == vrf_filter for _, vrf in pairs):
        pairs = [(lr, vrf) for lr, vrf in pairs if vrf.name == vrf_filter]

    routes: list[Any] = []
    for lr, vrf in pairs:
        for cls in (VrfStaticRoute, VrfStaticRouteV6):
            for route in cls.refreshall(vrf):
                routes.append(
                    _TaggedObject(
                        route,
                        vrf=vrf.name,
                        logical_router=lr.name,
                        routing_engine=ROUTING_ENGINE_ADVANCED,
                    )
                )
    return routes


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
        """Active routing table entries.

        Routing-engine aware. On a legacy firewall this reads the virtual-router
        RIB; on one running the Advanced Routing Engine (PAN-OS 10.2+) it reads
        the ARE RIB instead and normalizes FRR's JSON into the same lean row
        shape, adding ``protocol``, ``vrf``, and ``logical_router``. ECMP routes
        fan out to one row per nexthop on both engines. Every response reports
        which engine answered in ``routing_engine``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = reject_panorama_target(client, "get_routing_table")
        if guard is not None:
            return guard
        engine = await detect_routing_engine(client, timeout=read_timeout())

        if engine == ROUTING_ENGINE_ADVANCED:
            try:
                result = op_to_dict(client, ARE_ROUTE_CMD)
            except PanDeviceError as e:
                return wrap_panos_error(e, "get_routing_table", "advanced-routing route")
            try:
                items = parse_are_routes(result)
            except ValueError as e:
                # Never degrade to an empty list here: an unreadable ARE payload
                # must not look like a firewall with no routes.
                return {
                    "error": (
                        "This firewall runs the Advanced Routing Engine, but its "
                        f"'show advanced-routing route' response could not be parsed: {e}. "
                        "This is NOT evidence that the firewall has no routes. Please "
                        "report this with the raw output of run_show_command for "
                        f"'{ARE_ROUTE_CMD}'."
                    ),
                    "routing_engine": engine,
                    "items": [],
                    "total": 0,
                    "count": 0,
                }
        else:
            result = op_to_dict(client, "<show><routing><route></route></routing></show>")
            items = _items_from_op_table(result, "flags", "entry") + _items_from_op_table(
                result, "entry", ""
            )
            # Some versions return ``{entry: [...]}`` directly; handle that too.
            if not items and isinstance(result.get("entry"), list):
                items = result["entry"]

        out = apply_shape(
            items,
            shape=SHAPE_ROUTE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if engine != ROUTING_ENGINE_UNKNOWN:
            out["routing_engine"] = engine
        return out

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
        """Static routes for a virtual router / VRF (defaults to 'default').

        Routing-engine aware. On a legacy firewall this reads the named virtual
        router's routes (and errors if that VR doesn't exist). On a firewall
        running the Advanced Routing Engine there are no virtual routers —
        static routes live under logical routers and their VRFs — so
        ``virtual_router`` is matched against VRF names instead, and each row is
        tagged with ``vrf`` and ``logical_router``. If the name matches no VRF,
        every VRF is returned rather than nothing, so a legacy VR name can't
        produce a misleading empty result.

        Template-aware: on a Panorama, routers live in templates, so it walks
        every template and reads **both** engines' config, tagging each row with
        its source ``template`` and its own ``routing_engine`` — a
        Panorama-managed estate can legitimately be mixed. A template whose read
        times out is listed in ``timed_out``.
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
            return [
                _TaggedObject(r, routing_engine=ROUTING_ENGINE_LEGACY)
                for r in StaticRoute.refreshall(target)
            ]

        if isinstance(client, Panorama):
            # The engine is a per-template setting here, so read both trees
            # rather than picking one; a template using the other engine simply
            # contributes nothing.
            def _refresh_both(parent: Any) -> Any:
                rows: list[Any] = list(_refresh_routes(parent))
                # A template using the other engine simply has no such tree.
                with contextlib.suppress(PanDeviceError):
                    rows.extend(_are_static_routes(parent, virtual_router))
                return rows

            rows, timed_out = await gather_template_objects(
                client, _refresh_both, timeout=timeout_s
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

        engine = await detect_routing_engine(client, timeout=timeout_s)

        if engine == ROUTING_ENGINE_ADVANCED:
            try:
                are_rows = await run_blocking_timeout(
                    timeout_s, _are_static_routes, client, virtual_router
                )
            except PanDeviceError as e:
                return wrap_panos_error(e, "get_static_routes", virtual_router)
            shaped_are = apply_shape(
                panos_object_dicts(are_rows),
                shape=SHAPE_STATIC_ROUTE,
                verbose=verbose,
                fields=fields,
                pagination=pagination,
                pattern=pattern,
            )
            shaped_are["routing_engine"] = engine
            return shaped_are

        # Legacy firewall: preserve the explicit "VR not found" error.
        vrs = await run_blocking_timeout(timeout_s, VirtualRouter.refreshall, client)
        target_vr = next((v for v in vrs if v.name == virtual_router), None)
        if target_vr is None:
            missing: dict[str, Any] = {
                "error": f"Virtual router '{virtual_router}' not found.",
                "items": [],
                "total": 0,
                "count": 0,
            }
            if engine != ROUTING_ENGINE_UNKNOWN:
                missing["routing_engine"] = engine
            return missing
        routes = await run_blocking_timeout(timeout_s, StaticRoute.refreshall, target_vr)
        shaped = apply_shape(
            panos_object_dicts(routes),
            shape=SHAPE_STATIC_ROUTE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if engine != ROUTING_ENGINE_UNKNOWN:
            shaped["routing_engine"] = engine
        return shaped

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
        engine = await detect_routing_engine(client, timeout=read_timeout())
        blocked = reject_are_vr_write(engine, "add_static_route", name)
        if blocked is not None:
            return blocked
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
        engine = await detect_routing_engine(client, timeout=read_timeout())
        blocked = reject_are_vr_write(engine, "delete_static_route", name)
        if blocked is not None:
            return blocked
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
