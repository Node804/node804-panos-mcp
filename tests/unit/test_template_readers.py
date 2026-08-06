"""Template-scoped network readers walk all templates on a Panorama.

Zones, VLANs, and static routes live in Panorama **templates**, not a
firewall-local tree — so the firewall-scoped readers saw nothing there. They now
walk every template via ``gather_template_objects``, tagging each row with its
source ``template`` and skipping (recording) any template that times out.
Firewall behavior is unchanged (single read, no template tag).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.errors import PanDeviceError
from panos.network import Vlan, Zone
from panos.panorama import Panorama, Template

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.network import register_network_tools


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


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


async def _call(mcp: FastMCP, name: str, **kwargs: Any) -> Any:
    tool = (mcp._tool_manager._tools or {}).get(name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{name}' not registered")
    return await tool.fn(**kwargs)


class _FakeObj:
    def __init__(self, **data: Any) -> None:
        self._data = data
        self.name = data.get("name")

    def about(self) -> dict[str, Any]:
        return dict(self._data)


class _Xapi:
    """Stand-in for pan-os-python's xapi: ``show(xpath=...)`` returns a dict."""

    def __init__(self, show_fn: Any) -> None:
        self._show_fn = show_fn

    def show(self, xpath: str | None = None, **_kw: Any) -> Any:
        return self._show_fn(xpath)


class TestTemplateAwareReaders:
    @pytest.mark.asyncio
    async def test_vlans_walk_templates_tagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pano = Panorama("h", "u", "p")
        templates = [Template("Branch-TMPL"), Template("DC-TMPL")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(Template, "refreshall", staticmethod(lambda *a, **k: templates))

        def _vlan_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            return [_FakeObj(name=f"{parent.name}-vlan", interface="ae1")]

        monkeypatch.setattr(Vlan, "refreshall", staticmethod(_vlan_refresh))
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_vlans")

        by_name = {i["name"]: i["template"] for i in result["items"]}
        assert by_name == {"Branch-TMPL-vlan": "Branch-TMPL", "DC-TMPL-vlan": "DC-TMPL"}

    @pytest.mark.asyncio
    async def test_zones_walk_templates_via_vsys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pano = Panorama("h", "u", "p")
        templates = [Template("T1")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(Template, "refreshall", staticmethod(lambda *a, **k: templates))

        def _zone_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            # parent is a Vsys whose parent is the Template (set by .add()).
            tmpl_name = parent.parent.name
            return [_FakeObj(name=f"{tmpl_name}-trust", network={})]

        monkeypatch.setattr(Zone, "refreshall", staticmethod(_zone_refresh))
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_zones")

        assert result["total"] == 1
        assert result["items"][0]["name"] == "T1-trust"
        assert result["items"][0]["template"] == "T1"

    @pytest.mark.asyncio
    async def test_firewall_unchanged_no_template_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        monkeypatch.setattr(
            Vlan, "refreshall", staticmethod(lambda *a, **k: [_FakeObj(name="vlan.1")])
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_vlans", firewall="fw1")

        assert result["total"] == 1
        assert "template" not in result["items"][0]

    @pytest.mark.asyncio
    async def test_template_timeout_skipped_and_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        monkeypatch.setenv("PANOS_READ_TIMEOUT", "0.2")
        release = threading.Event()
        pano = Panorama("h", "u", "p")
        templates = [Template("T-ok"), Template("T-stuck")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(Template, "refreshall", staticmethod(lambda *a, **k: templates))

        def _vlan_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            if parent.name == "T-stuck":
                release.wait(timeout=10)
                return []
            return [_FakeObj(name="T-ok-vlan")]

        monkeypatch.setattr(Vlan, "refreshall", staticmethod(_vlan_refresh))
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        try:
            result = await _call(mcp, "get_vlans")
        finally:
            release.set()

        assert {i["name"] for i in result["items"]} == {"T-ok-vlan"}
        assert result["timed_out"] == ["T-stuck"]


class TestTemplateXpathReaders:
    """The unmodeled config readers (dns-proxy, GP, User-ID) walk templates via xpath."""

    @pytest.mark.asyncio
    async def test_dns_proxy_walks_templates_via_xpath(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pano = Panorama("h", "u", "p")
        templates = [Template("T1"), Template("T2")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(Template, "refreshall", staticmethod(lambda *a, **k: templates))

        def _show(xpath: str | None) -> dict[str, Any]:
            if "template/entry[@name='T1']" in (xpath or ""):
                return {"dns-proxy": {"entry": {"@_name": "corp-dns", "interface": "eth1"}}}
            raise PanDeviceError("No such node")  # T2 has none

        # get_dns_proxy reads via gather_template_config (in _common), which
        # calls config_xpath_to_dict from its own module namespace.
        monkeypatch.setattr(
            "panos_mcp.tools._common.config_xpath_to_dict",
            lambda _client, xpath: _show(xpath),
        )
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_dns_proxy")

        assert result["total"] == 1
        assert result["items"][0]["name"] == "corp-dns"
        assert result["items"][0]["template"] == "T1"

    @pytest.mark.asyncio
    async def test_dns_proxy_firewall_no_template_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"
                self.xapi = _Xapi(self._show)

            def _show(self, xpath: str | None) -> dict[str, Any]:
                return {"dns-proxy": {"entry": {"@_name": "local-dns", "interface": "eth0"}}}

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        ctx, mcp = _make_ctx()
        register_network_tools(ctx)

        result = await _call(mcp, "get_dns_proxy", firewall="fw1")

        assert result["total"] == 1
        assert result["items"][0]["name"] == "local-dns"
        assert "template" not in result["items"][0]
