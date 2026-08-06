"""Advanced Routing Engine (ARE) detection and the guards built on it.

PAN-OS 10.2 introduced ARE, an FRRouting-based stack that replaces the legacy
Virtual Router. The legacy op command still *parses* on an ARE box — it walks an
empty legacy RIB and returns a well-formed empty response — so a route reader
silently reported "total: 0" on a firewall with a fully populated ARE RIB.

These tests pin: engine detection and its memoization; the FRR-JSON route
parser (driven from captured XML through the real ``element_to_dict``, since the
XML→dict step is where a wrong assumption about the payload would hide); the
per-engine dispatch in both route readers; the mixed-engine template walk on
Panorama; and the write guard that stops a legacy virtual-router write from
landing as a silent no-op on an ARE device.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Parses only the local, checked-in fixture below — never network input.
from xml.etree import ElementTree

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.errors import PanDeviceError
from panos.network import (
    LogicalRouter,
    StaticRoute,
    VirtualRouter,
    Vrf,
    VrfStaticRoute,
    VrfStaticRouteV6,
)
from panos.panorama import Panorama, Template

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import (
    ROUTING_ENGINE_ADVANCED,
    ROUTING_ENGINE_LEGACY,
    ROUTING_ENGINE_UNKNOWN,
    ToolContext,
    detect_routing_engine,
    element_to_dict,
)
from panos_mcp.tools.network import (
    ARE_CONNECTED_NEXTHOP,
    ARE_ROUTE_CMD,
    parse_are_routes,
    register_network_tools,
)

_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    fw_module._entries = []
    reset_client_cache()
    yield
    fw_module._entries = []
    reset_client_cache()
    from panos.firewall import Firewall as RealFirewall

    client_module.Firewall = RealFirewall


def _make_ctx(mode: Mode = Mode.READ) -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=mode, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


async def _call(mcp: FastMCP, tool_name: str, /, **kwargs: Any) -> Any:
    # Positional-only: the write tools take their own ``name`` argument, which
    # would otherwise collide with this helper's parameter.
    tool = (mcp._tool_manager._tools or {}).get(tool_name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{tool_name}' not registered")
    return await tool.fn(**kwargs)


class _FakeFw:
    """Minimal stand-in for a pan-os-python Firewall (attribute-settable)."""

    def __init__(self, **kwargs: Any) -> None:
        self.hostname = "fw1"
        self.op_calls: list[str] = []
        self.op_result: dict[str, Any] = {}

    def op(self, cmd: str, cmd_xml: bool = False) -> dict[str, Any]:
        self.op_calls.append(cmd)
        return self.op_result


def _register_fw(monkeypatch: pytest.MonkeyPatch, fw: _FakeFw) -> None:
    """Make ``ctx.resolve('fw1')`` hand back ``fw``."""
    monkeypatch.setattr(client_module, "Firewall", lambda **kw: fw)
    fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))


def _xpath_responder(monkeypatch: pytest.MonkeyPatch, responses: dict[str, Any]) -> list[str]:
    """Route ``config_xpath_to_dict`` to a canned map; returns the call log.

    Keys are matched as substrings of the requested xpath. A key mapped to an
    exception instance is raised (PAN-OS "No such node" behavior).
    """
    seen: list[str] = []

    def _fake(_client: Any, xpath: str) -> dict[str, Any]:
        seen.append(xpath)
        for fragment, value in responses.items():
            if fragment in xpath:
                if isinstance(value, Exception):
                    raise value
                return value
        raise PanDeviceError("No such node")

    monkeypatch.setattr("panos_mcp.tools._common.config_xpath_to_dict", _fake)
    return seen


# ── Detection ───────────────────────────────────────────────────────────────


class TestDetectRoutingEngine:
    @pytest.mark.asyncio
    async def test_flag_yes_means_advanced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        assert await detect_routing_engine(_FakeFw(), timeout=5) == ROUTING_ENGINE_ADVANCED

    @pytest.mark.asyncio
    async def test_alternate_flag_spelling_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # PAN-OS spells it ``advance-routing``; accept the intuitive spelling
        # too rather than betting the whole feature on one string.
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advanced-routing": "yes"}}}
        )
        assert await detect_routing_engine(_FakeFw(), timeout=5) == ROUTING_ENGINE_ADVANCED

    @pytest.mark.asyncio
    async def test_logical_router_presence_is_fallback_signal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Flag subtree exists but carries no routing key — the LR probe decides.
        _xpath_responder(
            monkeypatch,
            {
                "deviceconfig/setting": {"setting": {"management": {}}},
                "network/logical-router": {"logical-router": {"entry": [{"@_name": "lr1"}]}},
            },
        )
        assert await detect_routing_engine(_FakeFw(), timeout=5) == ROUTING_ENGINE_ADVANCED

    @pytest.mark.asyncio
    async def test_flag_no_and_no_logical_routers_is_legacy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "no"}}}
        )
        assert await detect_routing_engine(_FakeFw(), timeout=5) == ROUTING_ENGINE_LEGACY

    @pytest.mark.asyncio
    async def test_probe_failure_falls_back_to_legacy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Every probe errors: a detection we can't complete must never make a
        # working legacy firewall worse.
        _xpath_responder(monkeypatch, {})
        assert await detect_routing_engine(_FakeFw(), timeout=5) == ROUTING_ENGINE_LEGACY

    @pytest.mark.asyncio
    async def test_panorama_is_unknown_not_guessed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The engine is a per-device (per-template) setting; a Panorama
        # appliance has no single answer.
        seen = _xpath_responder(monkeypatch, {})
        engine = await detect_routing_engine(Panorama("h", "u", "p"), timeout=5)
        assert engine == ROUTING_ENGINE_UNKNOWN
        assert seen == []  # short-circuits before any probe

    @pytest.mark.asyncio
    async def test_result_is_memoized_per_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        fw = _FakeFw()
        assert await detect_routing_engine(fw, timeout=5) == ROUTING_ENGINE_ADVANCED
        first = len(seen)
        assert await detect_routing_engine(fw, timeout=5) == ROUTING_ENGINE_ADVANCED
        assert len(seen) == first  # no second round trip


# ── get_routing_table ───────────────────────────────────────────────────────


class TestAreRouteParsing:
    """The ARE payload is FRR JSON inside a <json> element, not XML rows.

    These go through the real ``element_to_dict`` converter from captured XML
    rather than hand-built dicts, because the XML→dict step is exactly where a
    wrong assumption about the response shape would hide.
    """

    def test_parses_captured_xml_end_to_end(self) -> None:
        root = ElementTree.fromstring(_FIXTURES.joinpath("are_show_route.xml").read_text())
        result = element_to_dict(root.find("./result"))

        rows = parse_are_routes(result)

        # 0.0.0.0/0 has two nexthops → two rows; the other two prefixes one each.
        assert len(rows) == 4
        by_dest: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_dest.setdefault(row["destination"], []).append(row)
        assert set(by_dest) == {"0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12"}

    def test_ecmp_fans_out_one_row_per_nexthop(self) -> None:
        root = ElementTree.fromstring(_FIXTURES.joinpath("are_show_route.xml").read_text())
        rows = parse_are_routes(element_to_dict(root.find("./result")))

        default_rows = [r for r in rows if r["destination"] == "0.0.0.0/0"]
        assert len(default_rows) == 2
        assert {r["interface"] for r in default_rows} == {"ethernet1/1", "ethernet1/2"}

    def test_scope_and_protocol_fields_populated(self) -> None:
        root = ElementTree.fromstring(_FIXTURES.joinpath("are_show_route.xml").read_text())
        rows = parse_are_routes(element_to_dict(root.find("./result")))

        bgp = next(r for r in rows if r["destination"] == "10.0.0.0/8")
        assert bgp["protocol"] == "bgp"
        assert bgp["nexthop"] == "192.168.1.1"  # real next-hop address
        assert bgp["vrf"] == "default"
        assert bgp["logical_router"] == "public-lr"
        assert bgp["flags"] == "A"  # FRR pads its flag string; we strip it

        guest = next(r for r in rows if r["destination"] == "172.16.0.0/12")
        assert guest["vrf"] == "guest"
        assert guest["logical_router"] == "private-lr"

    def test_directly_connected_nexthop_is_explicit_not_missing(self) -> None:
        # A missing key would be stripped by drop-None and make the row list
        # schema-inconsistent; every row must carry a nexthop value.
        root = ElementTree.fromstring(_FIXTURES.joinpath("are_show_route.xml").read_text())
        rows = parse_are_routes(element_to_dict(root.find("./result")))

        assert all(r["nexthop"] is not None for r in rows)
        connected = [r for r in rows if r["nexthop"] == ARE_CONNECTED_NEXTHOP]
        assert len(connected) == 3

    def test_bare_prefix_map_without_logical_router_wrapper(self) -> None:
        # A single-LR device can return FRR's bare prefix map.
        rows = parse_are_routes(
            {"json": json.dumps({"0.0.0.0/0": [{"prefix": "0.0.0.0/0", "protocol": "static"}]})}
        )
        assert len(rows) == 1
        assert rows[0]["destination"] == "0.0.0.0/0"
        assert rows[0]["logical_router"] is None

    @pytest.mark.parametrize(
        "payload",
        [{}, {"json": "not json at all"}, {"json": 42}, {"json": "[1, 2]"}],
        ids=["missing", "undecodable", "wrong-type", "not-an-object"],
    )
    def test_unusable_payload_raises_rather_than_returning_empty(
        self, payload: dict[str, Any]
    ) -> None:
        with pytest.raises(ValueError):
            parse_are_routes(payload)


class TestRoutingTableDispatch:
    @pytest.mark.asyncio
    async def test_are_firewall_reads_the_are_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = ElementTree.fromstring(_FIXTURES.joinpath("are_show_route.xml").read_text())
        fw = _FakeFw()
        fw.op_result = element_to_dict(root.find("./result"))
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_routing_table", firewall="fw1")

        assert result["routing_engine"] == "advanced"
        assert result["total"] == 4
        assert fw.op_calls == [ARE_ROUTE_CMD]  # never issues the legacy command
        assert {i["protocol"] for i in result["items"]} == {"static", "bgp"}

    @pytest.mark.asyncio
    async def test_lean_view_carries_every_field_the_report_asked_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The upstream report asked specifically for prefix, protocol, nexthop,
        # interface, distance/metric and vrf in the lean shape. Route selection
        # is longest-prefix then distance then metric, so distance in
        # particular must not require a second verbose call.
        root = ElementTree.fromstring(_FIXTURES.joinpath("are_show_route.xml").read_text())
        fw = _FakeFw()
        fw.op_result = element_to_dict(root.find("./result"))
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_routing_table", firewall="fw1")

        expected = {"destination", "protocol", "nexthop", "interface", "distance", "metric", "vrf"}
        for item in result["items"]:
            assert expected <= set(item), f"lean row missing {expected - set(item)}"

    @pytest.mark.asyncio
    async def test_unparseable_are_payload_errors_not_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fw = _FakeFw()
        fw.op_result = {}  # no <json> element
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_routing_table", firewall="fw1")

        assert result["total"] == 0
        assert "NOT evidence" in result["error"]
        assert result["routing_engine"] == "advanced"

    @pytest.mark.asyncio
    async def test_legacy_firewall_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fw = _FakeFw()
        fw.op_result = {
            "flags": {
                "entry": [
                    {
                        "destination": "0.0.0.0/0",
                        "nexthop": "10.0.0.1",
                        "interface": "ethernet1/1",
                        "metric": "10",
                    }
                ]
            }
        }
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "no"}}}
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_routing_table", firewall="fw1")

        assert result["routing_engine"] == "legacy"
        assert result["total"] == 1
        assert result["items"][0]["destination"] == "0.0.0.0/0"
        assert fw.op_calls == ["<show><routing><route></route></routing></show>"]


# ── get_static_routes ───────────────────────────────────────────────────────


class _FakeVrfRoute:
    def __init__(self, name: str, destination: str) -> None:
        self.name = name
        self._destination = destination

    def about(self) -> dict[str, Any]:
        return {"name": self.name, "destination": self._destination, "nexthop": "10.0.0.1"}


def _stub_are_config(
    monkeypatch: pytest.MonkeyPatch, tree: dict[str, dict[str, list[Any]]]
) -> None:
    """Stub LogicalRouter/Vrf/VrfStaticRoute as ``{lr: {vrf: [routes]}}``."""

    class _Named:
        def __init__(self, name: str) -> None:
            self.name = name

    monkeypatch.setattr(
        LogicalRouter, "refreshall", staticmethod(lambda *a, **k: [_Named(n) for n in tree])
    )
    monkeypatch.setattr(
        Vrf,
        "refreshall",
        staticmethod(lambda lr, *a, **k: [_Named(n) for n in tree[lr.name]]),
    )

    def _routes(vrf: Any, *_a: Any, **_k: Any) -> list[Any]:
        for vrfs in tree.values():
            if vrf.name in vrfs:
                return vrfs[vrf.name]
        return []

    monkeypatch.setattr(VrfStaticRoute, "refreshall", staticmethod(_routes))
    monkeypatch.setattr(VrfStaticRouteV6, "refreshall", staticmethod(lambda *a, **k: []))


class TestStaticRoutesOnAre:
    @pytest.mark.asyncio
    async def test_are_firewall_reads_vrf_routes_tagged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        _stub_are_config(monkeypatch, {"lr1": {"default": [_FakeVrfRoute("r1", "10.0.0.0/8")]}})
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_static_routes", firewall="fw1")

        assert result["routing_engine"] == "advanced"
        assert result["total"] == 1
        row = result["items"][0]
        assert row["name"] == "r1"
        assert row["vrf"] == "default"
        assert row["logical_router"] == "lr1"

    @pytest.mark.asyncio
    async def test_unmatched_vrf_name_returns_all_not_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The caller's legacy VR name doesn't exist as a VRF. Returning zero
        # rows would recreate the false negative this feature exists to fix.
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        _stub_are_config(
            monkeypatch,
            {
                "lr1": {
                    "corp": [_FakeVrfRoute("r1", "10.0.0.0/8")],
                    "guest": [_FakeVrfRoute("r2", "172.16.0.0/12")],
                }
            },
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_static_routes", firewall="fw1", virtual_router="default")

        assert result["total"] == 2
        assert {i["vrf"] for i in result["items"]} == {"corp", "guest"}

    @pytest.mark.asyncio
    async def test_matching_vrf_name_filters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )
        _stub_are_config(
            monkeypatch,
            {
                "lr1": {
                    "corp": [_FakeVrfRoute("r1", "10.0.0.0/8")],
                    "guest": [_FakeVrfRoute("r2", "172.16.0.0/12")],
                }
            },
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_static_routes", firewall="fw1", virtual_router="guest")

        assert result["total"] == 1
        assert result["items"][0]["vrf"] == "guest"

    @pytest.mark.asyncio
    async def test_vr_not_found_on_legacy_keeps_original_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "no"}}}
        )
        monkeypatch.setattr(VirtualRouter, "refreshall", staticmethod(lambda *a, **k: []))
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_static_routes", firewall="fw1", virtual_router="typo")

        assert result["error"] == "Virtual router 'typo' not found."
        assert "note" not in result


class TestMixedEstateOnPanorama:
    @pytest.mark.asyncio
    async def test_template_walk_reads_both_engines_tagged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A Panorama-managed estate can legitimately be mixed: the routing
        # engine is a per-template setting, so reading only one tree would
        # silently drop half the fleet's static routes.
        pano = Panorama("h", "u", "p")
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(
            Template,
            "refreshall",
            staticmethod(lambda *a, **k: [Template("Legacy-TMPL"), Template("ARE-TMPL")]),
        )

        class _VR:
            name = "default"

        def _vr_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            return [_VR()] if parent.name == "Legacy-TMPL" else []

        monkeypatch.setattr(VirtualRouter, "refreshall", staticmethod(_vr_refresh))
        monkeypatch.setattr(
            StaticRoute,
            "refreshall",
            staticmethod(lambda *a, **k: [_FakeVrfRoute("legacy-r1", "10.0.0.0/8")]),
        )

        class _Named:
            def __init__(self, name: str) -> None:
                self.name = name

        def _lr_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            return [_Named("lr1")] if parent.name == "ARE-TMPL" else []

        monkeypatch.setattr(LogicalRouter, "refreshall", staticmethod(_lr_refresh))
        monkeypatch.setattr(Vrf, "refreshall", staticmethod(lambda *a, **k: [_Named("default")]))
        monkeypatch.setattr(
            VrfStaticRoute,
            "refreshall",
            staticmethod(lambda *a, **k: [_FakeVrfRoute("are-r1", "172.16.0.0/12")]),
        )
        monkeypatch.setattr(VrfStaticRouteV6, "refreshall", staticmethod(lambda *a, **k: []))

        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_static_routes")

        by_name = {i["name"]: i for i in result["items"]}
        assert set(by_name) == {"legacy-r1", "are-r1"}
        assert by_name["legacy-r1"]["routing_engine"] == "legacy"
        assert by_name["legacy-r1"]["template"] == "Legacy-TMPL"
        assert by_name["are-r1"]["routing_engine"] == "advanced"
        assert by_name["are-r1"]["template"] == "ARE-TMPL"
        assert by_name["are-r1"]["logical_router"] == "lr1"


# ── Write guard ─────────────────────────────────────────────────────────────


class TestAreWriteGuard:
    @pytest.mark.asyncio
    async def test_add_static_route_refused_on_are(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )

        def _boom(*_a: Any, **_k: Any) -> Any:  # pragma: no cover — must not run
            raise AssertionError("write path reached on an ARE firewall")

        monkeypatch.setattr(VirtualRouter, "refreshall", staticmethod(_boom))
        monkeypatch.setattr(StaticRoute, "create", _boom)
        ctx, mcp = _make_ctx(Mode.FULL)
        register_network_tools(ctx)

        result = await _call(
            mcp,
            "add_static_route",
            name="r1",
            destination="10.0.0.0/8",
            nexthop_type="ip-address",
            nexthop_value="10.0.0.1",
            firewall="fw1",
        )

        assert result["success"] is False
        assert "never enter the RIB" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_static_route_refused_on_are(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "yes"}}}
        )

        def _boom(*_a: Any, **_k: Any) -> Any:  # pragma: no cover — must not run
            raise AssertionError("write path reached on an ARE firewall")

        monkeypatch.setattr(VirtualRouter, "refreshall", staticmethod(_boom))
        ctx, mcp = _make_ctx(Mode.FULL)
        register_network_tools(ctx)

        result = await _call(mcp, "delete_static_route", name="r1", firewall="fw1")

        assert result["success"] is False
        assert "Advanced Routing Engine" in result["error"]

    @pytest.mark.asyncio
    async def test_legacy_write_path_still_reached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fw = _FakeFw()
        _register_fw(monkeypatch, fw)
        _xpath_responder(
            monkeypatch, {"deviceconfig/setting": {"setting": {"advance-routing": "no"}}}
        )

        class _VR:
            name = "default"

            def add(self, _obj: Any) -> None:
                return None

        monkeypatch.setattr(VirtualRouter, "refreshall", staticmethod(lambda *a, **k: [_VR()]))
        created: list[str] = []
        monkeypatch.setattr(StaticRoute, "create", lambda self: created.append(self.name))
        ctx, mcp = _make_ctx(Mode.FULL)
        register_network_tools(ctx)

        result = await _call(
            mcp,
            "add_static_route",
            name="r1",
            destination="10.0.0.0/8",
            nexthop_type="ip-address",
            nexthop_value="10.0.0.1",
            firewall="fw1",
        )

        assert result["success"] is True
        assert created == ["r1"]
