"""Firewall object readers are scope-aware: on a Panorama they walk shared + DGs.

Previously ``get_address_objects`` & friends called ``refreshall(client)``, which
on a Panorama reads only the shared scope — silently omitting every device
group. They now walk shared + every DG via ``gather_scoped_objects``, tagging
each object with its ``scope`` and skipping (recording) any DG that times out.
Firewall behavior is unchanged (single vsys read, no scope tag).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.objects import AddressObject
from panos.panorama import DeviceGroup, Panorama

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.objects import register_objects_tools


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


class TestScopeAwareObjectReaders:
    @pytest.mark.asyncio
    async def test_panorama_walks_shared_and_device_groups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pano = Panorama("h", "u", "p")
        dgs = [DeviceGroup("DG-A"), DeviceGroup("DG-B")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))

        def _addr_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            if isinstance(parent, DeviceGroup):
                return [_FakeObj(name=f"{parent.name}-web", ip_netmask="10.0.0.1/32")]
            # parent is the Panorama → shared scope
            return [_FakeObj(name="shared-dns", ip_netmask="8.8.8.8/32")]

        monkeypatch.setattr(AddressObject, "refreshall", staticmethod(_addr_refresh))
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        result = await _call(mcp, "get_address_objects")

        by_name = {i["name"]: i["scope"] for i in result["items"]}
        assert by_name == {
            "shared-dns": "shared",
            "DG-A-web": "DG-A",
            "DG-B-web": "DG-B",
        }
        assert result["total"] == 3

    @pytest.mark.asyncio
    async def test_firewall_unchanged_no_scope_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        monkeypatch.setattr(
            AddressObject,
            "refreshall",
            staticmethod(lambda *a, **k: [_FakeObj(name="local-web", ip_netmask="10.0.0.9/32")]),
        )
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        result = await _call(mcp, "get_address_objects", firewall="fw1")

        assert result["total"] == 1
        # Firewall rows carry no scope tag (single-scope response preserved).
        assert "scope" not in result["items"][0]

    @pytest.mark.asyncio
    async def test_device_group_timeout_is_skipped_and_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        monkeypatch.setenv("PANOS_READ_TIMEOUT", "0.2")
        release = threading.Event()
        pano = Panorama("h", "u", "p")
        dgs = [DeviceGroup("DG-A"), DeviceGroup("DG-stuck")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))

        def _addr_refresh(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            if isinstance(parent, DeviceGroup) and parent.name == "DG-stuck":
                release.wait(timeout=10)
                return []
            if isinstance(parent, DeviceGroup):
                return [_FakeObj(name="DG-A-web", ip_netmask="10.0.0.1/32")]
            return [_FakeObj(name="shared-dns", ip_netmask="8.8.8.8/32")]

        monkeypatch.setattr(AddressObject, "refreshall", staticmethod(_addr_refresh))
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        try:
            result = await _call(mcp, "get_address_objects")
        finally:
            release.set()

        names = {i["name"] for i in result["items"]}
        assert names == {"shared-dns", "DG-A-web"}  # stuck DG skipped
        assert result["timed_out"] == ["DG-stuck"]
