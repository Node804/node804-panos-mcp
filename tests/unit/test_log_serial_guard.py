"""Log queries are gated against serial-through-Panorama targets.

PAN-OS log retrieval (``type=log``) ignores the API ``target`` serial-redirect:
Panorama answers from its aggregated log database rather than the named
device's local logs. So a log query aimed at a serial-proxy firewall silently
returns fleet-wide, Panorama-role-masked logs — neither device-scoped nor what
the caller asked for. ``reject_serial_log_query`` turns that trap into a clean
error; every log tool runs it first. See ``panos_mcp.tools._common`` and
``panos_mcp.tools.logs``.
"""

from __future__ import annotations

from typing import Any

import pytest
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig
from panos.firewall import Firewall
from panos.panorama import Panorama

from panos_mcp.tools._common import ToolContext, reject_serial_log_query


def _serial_proxy_firewall() -> Firewall:
    """A Firewall routed through Panorama by serial — the shape the client factory builds."""
    pano = Panorama(hostname="10.0.0.1", api_key="k")
    fw = Firewall(serial="S1")
    pano.add(fw)
    return fw


class TestRejectSerialLogQuery:
    def test_serial_proxy_firewall_is_rejected(self) -> None:
        result = reject_serial_log_query(_serial_proxy_firewall(), "get_traffic_logs")
        assert result is not None
        assert "serial" in result["error"].lower()
        assert "direct connection" in result["error"].lower()
        # Stays schema-consistent with the log-response envelope.
        assert result["items"] == []
        assert result["total"] == 0
        assert result["count"] == 0

    def test_direct_firewall_passes(self) -> None:
        # A directly-connected firewall has no Panorama parent — its own local
        # logs are exactly what the caller wants, so the guard must not fire.
        fw = Firewall(hostname="10.0.0.9", api_key="k")
        assert reject_serial_log_query(fw, "get_traffic_logs") is None

    def test_panorama_target_passes(self) -> None:
        # Querying a Panorama directly returns its aggregated logs — legitimate
        # and honest about what it is, so it is not gated here.
        pano = Panorama(hostname="10.0.0.1", api_key="k")
        assert reject_serial_log_query(pano, "get_traffic_logs") is None


class TestLogToolGating:
    async def _call_traffic_logs(self, ctx: ToolContext) -> dict[str, Any]:
        from panos_mcp.tools.logs import register_logs_tools

        register_logs_tools(ctx)
        tool = (ctx.mcp._tool_manager._tools or {}).get("get_traffic_logs")  # type: ignore[attr-defined]
        assert tool is not None
        return await tool.fn()

    @pytest.mark.asyncio
    async def test_get_traffic_logs_rejects_serial_proxy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp.server.fastmcp import FastMCP

        import panos_mcp.tools._common as common_module

        mcp = FastMCP("test")
        ctx = ToolContext(
            mcp=mcp, gate=ModeGate(mode=Mode.READ, env_var="PANOS_MODE"), tls=TlsConfig()
        )
        # Resolution yields a serial-proxy firewall (ToolContext is frozen, so
        # patch the get_client that resolve() calls). The guard must fire before
        # any log query runs — no network call / xapi is touched.
        monkeypatch.setattr(
            common_module, "get_client", lambda firewall, tls: _serial_proxy_firewall()
        )
        result = await self._call_traffic_logs(ctx)
        assert "error" in result
        assert "serial" in result["error"].lower()
        assert result["items"] == []
