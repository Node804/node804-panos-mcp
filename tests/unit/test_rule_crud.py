"""Tests for Phase 5 rule CRUD tools.

Coverage focus:
  - Mode gating: rule CRUD registers only at Mode.FULL or above
  - Success path: pan-os-python create/delete/move called, success returned
  - Error path: PanDeviceError captured into {"error": ...} response
  - QoS xapi fallback path: xapi.set called with built XML, xpath built correctly

We test representative tools per category rather than every one — the
pattern is shared via _common helpers, so one passing test per category
demonstrates the pipeline works.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.errors import PanDeviceError

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.certificates import register_certificates_tools
from panos_mcp.tools.nat import register_nat_tools
from panos_mcp.tools.network import register_network_tools
from panos_mcp.tools.panorama import register_panorama_tools
from panos_mcp.tools.security import register_security_tools


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


def _seed_firewall(name: str = "fw1") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host="10.0.0.1", api_key="k"))


def _make_ctx(mode: Mode = Mode.FULL) -> tuple[ToolContext, FastMCP, ModeGate]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=mode, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp, gate


def _patch_fw(monkeypatch: pytest.MonkeyPatch, fake: Any) -> None:
    monkeypatch.setattr(client_module, "Firewall", fake)


async def _call(mcp: FastMCP, tool: str, **kwargs: Any) -> Any:
    entry = (mcp._tool_manager._tools or {}).get(tool)  # type: ignore[attr-defined]
    if entry is None:
        raise AssertionError(f"tool '{tool}' not registered")
    return await entry.fn(**kwargs)


def _fake_fw_class() -> type:
    """Build a FakeFw class with no-op add() and a mockable xapi."""

    class FakeFw:
        def __init__(self, **kwargs: Any) -> None:
            self.hostname = kwargs.get("hostname", "10.0.0.1")
            self.xapi = MagicMock()

        def add(self, child: Any) -> Any:
            child.parent = self
            return child

    return FakeFw


# --- Mode gating ---------------------------------------------------------


class TestModeGating:
    """Rule CRUD must register only when mode >= FULL."""

    def test_standard_mode_blocks_rule_crud(self) -> None:
        ctx, _mcp, gate = _make_ctx(Mode.STANDARD)
        register_security_tools(ctx)
        register_nat_tools(ctx)
        register_certificates_tools(ctx)
        register_network_tools(ctx)
        register_panorama_tools(ctx)

        enabled = set(gate.summary()["enabled_tools"])
        # Reads always available
        assert "get_security_rules" in enabled
        # Phase 5 rule CRUD blocked at standard mode
        for blocked in [
            "add_security_rule",
            "delete_security_rule",
            "move_security_rule",
            "set_security_rule_disabled",
            "add_nat_rule",
            "add_pbf_rule",
            "add_qos_rule",
            "add_decryption_rule",
            "add_static_route",
            "panorama_add_pre_rule",
            "panorama_add_post_rule",
            "panorama_add_device_group_nat_rule",
        ]:
            assert blocked not in enabled, f"{blocked} should be blocked in STANDARD mode"

    def test_full_mode_enables_all_rule_crud(self) -> None:
        ctx, _mcp, gate = _make_ctx(Mode.FULL)
        register_security_tools(ctx)
        register_nat_tools(ctx)
        register_certificates_tools(ctx)
        register_network_tools(ctx)
        register_panorama_tools(ctx)

        enabled = set(gate.summary()["enabled_tools"])
        expected = {
            # security (4)
            "add_security_rule",
            "delete_security_rule",
            "move_security_rule",
            "set_security_rule_disabled",
            # PBF (4)
            "add_pbf_rule",
            "delete_pbf_rule",
            "move_pbf_rule",
            "set_pbf_rule_disabled",
            # QoS (4)
            "add_qos_rule",
            "delete_qos_rule",
            "move_qos_rule",
            "set_qos_rule_disabled",
            # NAT (4)
            "add_nat_rule",
            "delete_nat_rule",
            "move_nat_rule",
            "set_nat_rule_disabled",
            # Decryption (4)
            "add_decryption_rule",
            "delete_decryption_rule",
            "move_decryption_rule",
            "set_decryption_rule_disabled",
            # Static routes (2)
            "add_static_route",
            "delete_static_route",
            # Panorama (9)
            "panorama_add_pre_rule",
            "panorama_delete_pre_rule",
            "panorama_move_pre_rule",
            "panorama_add_post_rule",
            "panorama_delete_post_rule",
            "panorama_move_post_rule",
            "panorama_add_device_group_nat_rule",
            "panorama_delete_device_group_nat_rule",
            "panorama_move_device_group_nat_rule",
        }
        missing = expected - enabled
        assert not missing, f"Phase 5 tools missing in FULL mode: {missing}"
        assert len(expected) == 31, "Phase 5 plan calls for 31 rule CRUD tools"


# --- Security rule CRUD --------------------------------------------------


class TestSecurityRuleCRUD:
    @pytest.mark.asyncio
    async def test_add_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.policies import SecurityRule

        monkeypatch.setattr(SecurityRule, "create", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp,
            "add_security_rule",
            name="block-tor",
            from_zones=["trust"],
            to_zones=["untrust"],
            source=["any"],
            destination=["any"],
            application=["tor"],
            service=["application-default"],
            action="deny",
            firewall="fw1",
        )
        assert result == {"success": True, "operation": "created", "name": "block-tor"}

    @pytest.mark.asyncio
    async def test_delete_propagates_panos_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.policies import SecurityRule

        monkeypatch.setattr(
            SecurityRule,
            "delete",
            MagicMock(side_effect=PanDeviceError("Rule not found")),
        )

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "delete_security_rule", name="missing", firewall="fw1")
        assert result["success"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_move_requires_destination_for_relative(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "move_security_rule", name="r1", where="before", firewall="fw1")
        assert result["success"] is False
        assert "destination" in result["error"]

    @pytest.mark.asyncio
    async def test_move_to_top_works_without_destination(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.policies import SecurityRule

        move_mock = MagicMock(return_value=None)
        monkeypatch.setattr(SecurityRule, "move", move_mock)

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "move_security_rule", name="r1", where="top", firewall="fw1")
        assert result["success"] is True
        move_mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_disabled_updates_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.policies import SecurityRule

        update_mock = MagicMock(return_value=None)
        monkeypatch.setattr(SecurityRule, "update", update_mock)

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp, "set_security_rule_disabled", name="r1", disabled=True, firewall="fw1"
        )
        assert result["success"] is True
        assert result["disabled"] is True
        update_mock.assert_called_once_with("disabled")


# --- QoS xapi fallback path ----------------------------------------------


class TestQosRuleCRUD:
    """QoS uses the xapi escape hatch because pan-os-python doesn't model QoS."""

    @pytest.mark.asyncio
    async def test_add_calls_xapi_set_with_built_xml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp,
            "add_qos_rule",
            name="prio-voice",
            from_zones=["trust"],
            to_zones=["untrust"],
            source=["any"],
            destination=["any"],
            application=["sip", "rtp"],
            service=["any"],
            action_class="1",
            firewall="fw1",
        )
        assert result["success"] is True

        # The fake firewall's xapi.set should have been called once.
        client = client_module._CLIENTS["fw1"]
        client.xapi.set.assert_called_once()
        xpath_arg, element_arg = client.xapi.set.call_args[0]
        assert "/rulebase/qos/rules" in xpath_arg
        # Built XML must contain escaped name attribute + the class element.
        assert 'name="prio-voice"' in element_arg
        assert "<class>1</class>" in element_arg

    @pytest.mark.asyncio
    async def test_delete_calls_xapi_delete_with_rule_xpath(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "delete_qos_rule", name="prio-voice", firewall="fw1")
        assert result["success"] is True
        client = client_module._CLIENTS["fw1"]
        client.xapi.delete.assert_called_once()
        xpath_arg = client.xapi.delete.call_args[0][0]
        assert "entry[@name='prio-voice']" in xpath_arg

    @pytest.mark.asyncio
    async def test_xapi_panos_error_captured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_cls = _fake_fw_class()
        _patch_fw(monkeypatch, fake_cls)
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_security_tools(ctx)

        # First call constructs the client (and stashes it in cache).
        await _call(mcp, "delete_qos_rule", name="warm", firewall="fw1")
        # Now make xapi.set raise on the cached client.
        client = client_module._CLIENTS["fw1"]
        client.xapi.set.side_effect = PanDeviceError("Invalid class number")

        result = await _call(
            mcp,
            "add_qos_rule",
            name="bad",
            from_zones=["trust"],
            to_zones=["untrust"],
            source=["any"],
            destination=["any"],
            application=["any"],
            service=["any"],
            action_class="1",
            firewall="fw1",
        )
        assert result["success"] is False
        assert "Invalid class number" in result["error"]


# --- NAT, decryption, static route — one success path each ---------------


class TestOtherCategoriesSuccessPath:
    @pytest.mark.asyncio
    async def test_nat_add(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.policies import NatRule

        monkeypatch.setattr(NatRule, "create", MagicMock(return_value=None))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_nat_tools(ctx)
        result = await _call(
            mcp,
            "add_nat_rule",
            name="src-nat-1",
            from_zones=["trust"],
            to_zones=["untrust"],
            source=["any"],
            destination=["any"],
            firewall="fw1",
        )
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_decryption_add(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.policies import DecryptionRule

        monkeypatch.setattr(DecryptionRule, "create", MagicMock(return_value=None))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_certificates_tools(ctx)
        result = await _call(
            mcp,
            "add_decryption_rule",
            name="dec-1",
            from_zones=["trust"],
            to_zones=["untrust"],
            source=["any"],
            destination=["any"],
            service=["any"],
            action="decrypt",
            type="ssl-forward-proxy",
            firewall="fw1",
        )
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_static_route_add(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeVr:
            def __init__(self) -> None:
                self.name = "default"

            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.network import StaticRoute, VirtualRouter

        monkeypatch.setattr(VirtualRouter, "refreshall", staticmethod(lambda *a, **k: [FakeVr()]))
        monkeypatch.setattr(StaticRoute, "create", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_network_tools(ctx)
        result = await _call(
            mcp,
            "add_static_route",
            name="default-route",
            destination="0.0.0.0/0",
            nexthop_type="ip-address",
            nexthop_value="10.0.0.1",
            firewall="fw1",
        )
        assert result["success"] is True
        assert result["virtual_router"] == "default"


# --- Panorama pre/post/DG-NAT rule CRUD ----------------------------------


class TestPanoramaRuleCRUD:
    @pytest.mark.asyncio
    async def test_add_pre_rule_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeDg:
            def __init__(self) -> None:
                self.name = "hq-dg"

            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.panorama import DeviceGroup
        from panos.policies import SecurityRule

        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: [FakeDg()]))
        monkeypatch.setattr(SecurityRule, "create", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_panorama_tools(ctx)
        result = await _call(
            mcp,
            "panorama_add_pre_rule",
            device_group="hq-dg",
            name="pre-block",
            from_zones=["trust"],
            to_zones=["untrust"],
            source=["any"],
            destination=["any"],
            application=["any"],
            service=["any"],
            action="deny",
            firewall="fw1",
        )
        assert result["success"] is True
        assert result["device_group"] == "hq-dg"
        assert result["rulebase"] == "pre"

    @pytest.mark.asyncio
    async def test_unknown_device_group_returns_clean_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        from panos.panorama import DeviceGroup

        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: []))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_panorama_tools(ctx)
        result = await _call(
            mcp,
            "panorama_delete_pre_rule",
            device_group="nonexistent",
            name="r1",
            firewall="fw1",
        )
        assert result["success"] is False
        assert "nonexistent" in result["error"]
