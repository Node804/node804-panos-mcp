"""End-to-end tests for representative Phase 3 read tools.

We verify the full pipeline (resolve → pan-os-python call → shape → return)
against mock pan-os-python clients. Per category we test one tool that
exercises an op-command path and one that exercises the .refreshall path.
That gives confidence the patterns work without testing all 71 tools
individually.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.objects import register_objects_tools
from panos_mcp.tools.security import register_security_tools
from panos_mcp.tools.system import register_system_tools

# --- Test fixtures ---------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    fw_module._entries = []
    reset_client_cache()  # otherwise a Firewall from one test bleeds into the next
    yield
    fw_module._entries = []
    reset_client_cache()
    # Restore the real Firewall class in case a test patched it.
    from panos.firewall import Firewall as RealFirewall
    client_module.Firewall = RealFirewall


def _seed_firewall(name: str = "fw1", host: str = "10.0.0.1", key: str = "k") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host=host, api_key=key))


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


def _patch_firewall_class(monkeypatch: pytest.MonkeyPatch, fake_class: Any) -> None:
    """Replace pan-os-python's Firewall constructor with a fake.

    The :func:`get_client` factory imports Firewall from panos.firewall, so
    we patch the symbol re-exported in our client module.
    """
    import panos_mcp.client as client_module
    monkeypatch.setattr(client_module, "Firewall", fake_class)


async def _call(mcp: FastMCP, name: str, **kwargs: Any) -> Any:
    tool = (mcp._tool_manager._tools or {}).get(name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{name}' not registered")
    return await tool.fn(**kwargs)


# --- get_firewall_info (op-command path) ----------------------------------


class TestGetFirewallInfo:
    @pytest.mark.asyncio
    async def test_returns_lean_default_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeFw:
            hostname = "10.0.0.1"
            api_key = "k"
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "10.0.0.1")

            def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
                # op_to_dict accepts a dict directly when our converter sees one.
                return {"system": {
                    "hostname": "fw1",
                    "model": "PA-220",
                    "serial": "00112233",
                    "sw-version": "11.1.0",
                    "uptime": "5 days",
                    "ip-address": "10.0.0.1",
                    "multi-vsys": "no",
                    # Verbose-only fields:
                    "av-version": "4321-1234",
                    "platform-family": "pa-200",
                    "device-certificate-status": "Valid",
                }}

        _patch_firewall_class(monkeypatch, FakeFw)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)

        result = await _call(mcp, "get_firewall_info", firewall="fw1")

        assert result["hostname"] == "fw1"
        assert result["model"] == "PA-220"
        # Verbose-only fields excluded by default
        assert "av-version" not in result
        assert "platform-family" not in result

    @pytest.mark.asyncio
    async def test_verbose_includes_all_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")

            def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
                return {"system": {"hostname": "fw1", "av-version": "4321-1234"}}

        _patch_firewall_class(monkeypatch, FakeFw)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)

        result = await _call(mcp, "get_firewall_info", firewall="fw1", verbose=True)
        assert result["hostname"] == "fw1"
        assert result["av-version"] == "4321-1234"

    @pytest.mark.asyncio
    async def test_unresolved_firewall_returns_error(self) -> None:
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)
        result = await _call(mcp, "get_firewall_info", firewall="nonexistent")
        assert "error" in result
        assert "nonexistent" in result["error"]


# --- get_address_objects (refreshall path) --------------------------------


class TestGetAddressObjects:
    @pytest.mark.asyncio
    async def test_returns_paginated_lean_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Build 150 fake address objects to test pagination.
        class FakeAddr:
            def __init__(self, name: str) -> None:
                self.name = name
                self._data = {
                    "name": name,
                    "ip_netmask": "10.0.0.1/32",
                    "description": None,
                    "tag": ["a-tag"],
                    "uuid": "internal-uuid",
                }

            def about(self) -> dict[str, Any]:
                return self._data

        fake_objects = [FakeAddr(f"addr-{i}") for i in range(150)]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")

        # Patch refreshall to return our fake objects regardless of arguments.
        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.objects import AddressObject
        monkeypatch.setattr(AddressObject, "refreshall", staticmethod(lambda *a, **k: fake_objects))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        # Default pagination = limit 100, offset 0
        result = await _call(mcp, "get_address_objects", firewall="fw1")
        assert result["total"] == 150
        assert result["count"] == 100
        assert result["items"][0]["name"] == "addr-0"
        # Lean view drops description (None) and uuid (not in default_fields).
        assert "description" not in result["items"][0]
        assert "uuid" not in result["items"][0]

    @pytest.mark.asyncio
    async def test_pattern_filter_reduces_total(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeAddr:
            def __init__(self, name: str) -> None:
                self.name = name

            def about(self) -> dict[str, Any]:
                return {"name": self.name, "ip_netmask": "10.0.0.1/32"}

        fake_objects = [FakeAddr(n) for n in ["dmz-web", "internal-db", "dmz-mail"]]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.objects import AddressObject
        monkeypatch.setattr(AddressObject, "refreshall", staticmethod(lambda *a, **k: fake_objects))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        result = await _call(mcp, "get_address_objects", firewall="fw1", pattern="dmz")
        assert result["total"] == 2
        assert {i["name"] for i in result["items"]} == {"dmz-web", "dmz-mail"}


# --- get_security_rules (refreshall via Rulebase) ------------------------


class TestGetSecurityRules:
    @pytest.mark.asyncio
    async def test_lean_excludes_uuid_and_audit_comment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeRule:
            def __init__(self, name: str) -> None:
                self.name = name

            def about(self) -> dict[str, Any]:
                return {
                    "name": self.name,
                    "fromzone": ["trust"],
                    "tozone": ["untrust"],
                    "source": ["any"],
                    "destination": ["any"],
                    "application": ["web-browsing"],
                    "service": ["application-default"],
                    "action": "allow",
                    "disabled": False,
                    "uuid": "abc-def",
                    "audit_comment": "Approved by SecOps 2024-08-15",
                    "tag": ["compliance"],
                }

        rules = [FakeRule(f"rule-{i}") for i in range(5)]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "get_security_rules", firewall="fw1")
        assert result["count"] == 5
        for r in result["items"]:
            assert "uuid" not in r
            assert "audit_comment" not in r
            assert "tag" not in r
            assert r["action"] == "allow"
