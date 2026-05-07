"""Tests for panos_mcp.tools.status + panos_mcp.tools.firewalls.

We register the tools against a real FastMCP instance so the gate behavior
(register vs skip based on mode) is exercised end-to-end. The tools then
get called via FastMCP's internal handler dict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink

import panos_mcp.config.firewalls as fw_module
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.firewalls import register_firewall_tools
from panos_mcp.tools.status import register_status_tools


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    fw_module._entries = []
    yield
    fw_module._entries = []


async def _call_tool(mcp: FastMCP, name: str, **kwargs: Any) -> Any:
    """Invoke a registered tool's handler directly (bypasses MCP transport)."""
    tool = (mcp._tool_manager._tools or {}).get(name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{name}' not registered")
    # FastMCP stores the wrapped function under .fn
    return await tool.fn(**kwargs)


def _make_gate(mode: Mode = Mode.READ) -> ModeGate:
    return ModeGate(mode=mode, env_var="PANOS_MODE")


def _make_ctx(mcp: FastMCP, mode: Mode = Mode.READ, tls: TlsConfig | None = None) -> ToolContext:
    return ToolContext(mcp=mcp, gate=_make_gate(mode), tls=tls or TlsConfig())


# --- server_status ----------------------------------------------------------


class TestServerStatus:
    @pytest.mark.asyncio
    async def test_reports_active_mode_and_capabilities(self) -> None:
        mcp = FastMCP("test")
        gate = _make_gate(Mode.STANDARD)
        sink = open_sink({})
        register_status_tools(ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), audit_sink=sink)

        result = await _call_tool(mcp, "server_status")
        assert result["mode"] == "standard"
        assert result["capabilities"]["read"] is True
        assert result["capabilities"]["write_objects"] is True
        assert result["capabilities"]["write_rules"] is False
        assert result["capabilities"]["commit_and_raw_api"] is False

    @pytest.mark.asyncio
    async def test_reports_tls_posture(self) -> None:
        mcp = FastMCP("test")
        gate = _make_gate()
        register_status_tools(
            ToolContext(mcp=mcp, gate=gate, tls=TlsConfig(verify=False)),
            audit_sink=open_sink({}),
        )
        result = await _call_tool(mcp, "server_status")
        assert "verify=OFF" in result["tls"]

    @pytest.mark.asyncio
    async def test_reports_audit_state(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        sink = open_sink({"PANOS_AUDIT_LOG": str(log_path)}, env_var="PANOS_AUDIT_LOG")
        mcp = FastMCP("test")
        register_status_tools(_make_ctx(mcp), audit_sink=sink)
        result = await _call_tool(mcp, "server_status")
        assert "enabled" in result["audit"]
        assert str(log_path) in result["audit"]

    @pytest.mark.asyncio
    async def test_reports_firewall_registry(self) -> None:
        fw_module._entries = [
            FirewallEntry(name="hq", host="10.0.0.1", api_key="k1"),
            FirewallEntry(name="branch", host="10.0.0.2", api_key="k2"),
        ]
        mcp = FastMCP("test")
        register_status_tools(_make_ctx(mcp), audit_sink=open_sink({}))
        result = await _call_tool(mcp, "server_status")
        assert result["firewalls"]["multi_firewall"] is True
        names = {e["name"] for e in result["firewalls"]["configured"]}
        assert names == {"hq", "branch"}
        # Keys never surface
        assert "k1" not in str(result)
        assert "k2" not in str(result)

    def test_status_tool_always_registers_even_in_strict_mode(self) -> None:
        # server_status requires READ; even read mode (the most restrictive)
        # should expose it.
        mcp = FastMCP("test")
        gate = _make_gate(Mode.READ)
        register_status_tools(
            ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), audit_sink=open_sink({})
        )
        assert "server_status" in gate.summary()["enabled_tools"]


# --- list_firewalls --------------------------------------------------------


class TestListFirewalls:
    @pytest.mark.asyncio
    async def test_no_firewalls_reports_environment_mode(self) -> None:
        mcp = FastMCP("test")
        register_firewall_tools(_make_ctx(mcp))
        result = await _call_tool(mcp, "list_firewalls")
        assert result["mode"] == "environment"
        assert result["firewalls"] == []
        assert result["firewall_param_required"] is False

    @pytest.mark.asyncio
    async def test_single_entry_reports_single_mode(self) -> None:
        fw_module._entries = [FirewallEntry(name="only", host="10.0.0.1", api_key="k")]
        mcp = FastMCP("test")
        register_firewall_tools(_make_ctx(mcp))
        result = await _call_tool(mcp, "list_firewalls")
        assert result["mode"] == "single"
        assert result["firewall_param_required"] is False
        assert result["firewalls"] == [{"name": "only", "host": "10.0.0.1"}]

    @pytest.mark.asyncio
    async def test_multi_entry_requires_param(self) -> None:
        fw_module._entries = [
            FirewallEntry(name="a", host="10.0.0.1", api_key="k1"),
            FirewallEntry(name="b", host="10.0.0.2", api_key="k2"),
        ]
        mcp = FastMCP("test")
        register_firewall_tools(_make_ctx(mcp))
        result = await _call_tool(mcp, "list_firewalls")
        assert result["mode"] == "multi"
        assert result["firewall_param_required"] is True

    @pytest.mark.asyncio
    async def test_response_contains_no_api_keys(self) -> None:
        fw_module._entries = [
            FirewallEntry(name="fw", host="10.0.0.1", api_key="VERY-SECRET-KEY"),
        ]
        mcp = FastMCP("test")
        register_firewall_tools(_make_ctx(mcp))
        result = await _call_tool(mcp, "list_firewalls")
        assert "VERY-SECRET-KEY" not in str(result)
