"""The per-firewall dataplane/runtime read tools must reject a Panorama target.

Pointed at a Panorama these operational commands return an empty or error
response that reads, misleadingly, as "nothing configured". The guard turns
that into a clean, actionable error. ``get_system_resources`` is deliberately
excluded — Panorama has its own CPU/memory and answers that command — so it is
asserted to NOT be guarded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.panorama import Panorama

import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.aggregations import register_aggregation_tools
from panos_mcp.tools.network import register_network_tools
from panos_mcp.tools.system import register_system_tools
from panos_mcp.tools.threat import register_threat_tools
from panos_mcp.tools.userid import register_userid_tools
from panos_mcp.tools.vpn import register_vpn_tools


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


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


async def _call(mcp: FastMCP, name: str, **kwargs: Any) -> Any:
    tool = (mcp._tool_manager._tools or {}).get(name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{name}' not registered")
    return await tool.fn(**kwargs)


def _wire_panorama(monkeypatch: pytest.MonkeyPatch) -> Panorama:
    """Resolve every tool to a Panorama whose .op() would explode if called.

    A guarded tool must short-circuit before touching the network, so .op
    raising guarantees the guard ran rather than the command.
    """
    pano = Panorama("h", "u", "p")

    def _boom(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("op() should not run against a guarded Panorama target")

    monkeypatch.setattr(pano, "op", _boom)
    monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
    return pano


GUARDED = [
    (register_network_tools, "get_interfaces", {}),
    (register_network_tools, "get_routing_table", {}),
    (register_network_tools, "get_arp_table", {}),
    (register_network_tools, "get_dhcp_leases", {}),
    (register_vpn_tools, "get_ipsec_tunnels", {}),
    (register_vpn_tools, "get_globalprotect_users", {}),
    (register_userid_tools, "get_userid_mappings", {}),
    (register_userid_tools, "get_userid_groups", {}),
    (register_threat_tools, "get_wildfire_status", {}),
    (register_aggregation_tools, "get_rule_hit_counts", {}),
    (register_aggregation_tools, "unused_rules", {}),
]


class TestDataplaneToolsRejectPanorama:
    @pytest.mark.parametrize(("register", "tool", "kwargs"), GUARDED)
    @pytest.mark.asyncio
    async def test_returns_clean_error_not_op_call(
        self,
        monkeypatch: pytest.MonkeyPatch,
        register: Any,
        tool: str,
        kwargs: dict[str, Any],
    ) -> None:
        _wire_panorama(monkeypatch)
        ctx, mcp = _make_ctx()
        register(ctx)

        result = await _call(mcp, tool, **kwargs)

        assert isinstance(result, dict)
        assert "error" in result
        assert "Panorama" in result["error"]

    @pytest.mark.asyncio
    async def test_get_system_resources_is_not_guarded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Panorama answers 'show system resources', so the tool must run it."""
        pano = Panorama("h", "u", "p")
        called: dict[str, bool] = {"op": False}

        def _op(cmd: str, **kwargs: Any) -> dict[str, Any]:
            called["op"] = True
            return {"result": "CPU states: 5% user"}

        monkeypatch.setattr(pano, "op", _op)
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)

        result = await _call(mcp, "get_system_resources")

        assert called["op"] is True
        assert "error" not in result
