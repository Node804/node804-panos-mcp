"""Firewall-scoped config readers must redirect on a Panorama target.

These tools read the firewall-local rulebase/vsys config, which is empty (or
errors) on a Panorama — so an agent auditing policy gets a confidently-wrong
"nothing configured" answer. Each now returns a clean error naming the correct
device-group tool instead. The guard fires before any network call, so a bare
Panorama instance is enough to exercise it.
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
from panos_mcp.tools.admin import register_admin_tools
from panos_mcp.tools.aggregations import register_aggregation_tools
from panos_mcp.tools.nat import register_nat_tools
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


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


async def _call(mcp: FastMCP, name: str, **kwargs: Any) -> Any:
    tool = (mcp._tool_manager._tools or {}).get(name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{name}' not registered")
    return await tool.fn(**kwargs)


# (register_fn, tool_name, call_kwargs, substring the redirect must name)
REDIRECTS = [
    (register_security_tools, "get_security_rules", {}, "panorama_get_pre_rules"),
    (register_security_tools, "get_pbf_rules", {}, "rule_type='pbf'"),
    (register_security_tools, "get_qos_rules", {}, "get_config_xpath"),
    (register_nat_tools, "get_nat_rules", {}, "panorama_get_device_group_nat_rules"),
    (register_admin_tools, "get_admin_roles", {}, "panorama_get_admin_roles"),
    (
        register_aggregation_tools,
        "count_rules_by_action",
        {},
        "panorama_count_rules_per_device_group",
    ),
    (
        register_aggregation_tools,
        "find_rule_by_name",
        {"pattern": "x"},
        "panorama_walk_all_rules",
    ),
    (
        register_aggregation_tools,
        "summarize_security_policy",
        {},
        "panorama_summarize_security_policy",
    ),
]


class TestFirewallScopedReadersRedirectOnPanorama:
    @pytest.mark.parametrize(("register", "tool", "kwargs", "sibling"), REDIRECTS)
    @pytest.mark.asyncio
    async def test_redirects_to_named_sibling(
        self,
        monkeypatch: pytest.MonkeyPatch,
        register: Any,
        tool: str,
        kwargs: dict[str, Any],
        sibling: str,
    ) -> None:
        pano = Panorama("h", "u", "p")

        def _boom(*_a: Any, **_kw: Any) -> Any:
            raise AssertionError("guard must fire before any network call")

        monkeypatch.setattr(pano, "op", _boom)
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        ctx, mcp = _make_ctx()
        register(ctx)

        result = await _call(mcp, tool, **kwargs)

        assert isinstance(result, dict)
        assert "error" in result, f"{tool} should return an error on Panorama"
        assert "Panorama" in result["error"]
        assert sibling in result["error"], f"{tool} should name {sibling!r}"
