"""Serial-through-Panorama connections.

Covers the ``PANOS_ALLOW_SERIAL_CONNECTION`` opt-in: configured serial-proxy
entries, dynamic discovery of Panorama-managed devices, the gate that keeps it
off by default, and that direct entries always win. See
``panos_mcp.config.firewalls`` and ``panos_mcp.client``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import fromstring

import pytest
from node804_mcp_toolkit import TlsConfig
from panos.firewall import Firewall as RealFirewall
from panos.panorama import Panorama as RealPanorama
from pydantic import ValidationError

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import (
    DeviceInfo,
    ResolveError,
    discover_managed_devices,
    get_client,
    reset_client_cache,
)
from panos_mcp.config.firewalls import (
    FirewallEntry,
    list_firewall_entries,
    load_firewall_config,
    resolve_firewall,
    serial_connection_enabled,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    monkeypatch.delenv("PANOS_ALLOW_SERIAL_CONNECTION", raising=False)
    # Any real connection auto-detects as a Panorama in these tests. Detection
    # reads the model from the class-neutral ``show_system_info`` probe.
    from panos.base import PanDevice

    monkeypatch.setattr(
        PanDevice,
        "show_system_info",
        lambda self: {
            "system": {"model": "Panorama", "sw-version": "11.2.0", "serial": "PANO-SERIAL"}
        },
    )
    monkeypatch.setattr(
        PanDevice,
        "refresh_system_info",
        lambda self: ("11.2.0", "Panorama", "PANO-SERIAL"),
    )
    fw_module._entries = []
    reset_client_cache()
    yield
    fw_module._entries = []
    reset_client_cache()


def _seed(entry: FirewallEntry) -> None:
    fw_module._entries.append(entry)


# --- Model ------------------------------------------------------------------


class TestFirewallEntryModel:
    def test_serial_entry_is_proxy(self) -> None:
        e = FirewallEntry(name="edge", serial="00112233")
        assert e.is_proxy is True
        assert e.host is None

    def test_direct_entry_is_not_proxy(self) -> None:
        e = FirewallEntry(name="edge", host="10.0.0.1", api_key="k")
        assert e.is_proxy is False

    def test_host_present_wins_over_serial_for_is_proxy(self) -> None:
        # An entry with both host and serial is treated as direct.
        e = FirewallEntry(name="edge", host="10.0.0.1", serial="00112233", api_key="k")
        assert e.is_proxy is False

    def test_requires_host_or_serial(self) -> None:
        with pytest.raises(ValidationError):
            FirewallEntry(name="edge")

    def test_serial_stripped(self) -> None:
        assert FirewallEntry(name="edge", serial="  00112233  ").serial == "00112233"


# --- Flag -------------------------------------------------------------------


class TestSerialFlag:
    def test_off_by_default(self) -> None:
        assert serial_connection_enabled() is False

    @pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE", "On"])
    def test_truthy_values(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", value)
        assert serial_connection_enabled() is True

    @pytest.mark.parametrize("value", ["false", "0", "no", "", "nonsense"])
    def test_falsy_values(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", value)
        assert serial_connection_enabled() is False


# --- Registry load / view ---------------------------------------------------


class TestSerialEntryRegistry:
    def test_loads_serial_entry_without_keychain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No keyring backend at all — a serial entry must still load, since it
        # borrows Panorama's key rather than needing its own.
        monkeypatch.setattr(fw_module, "_keyring_available", lambda: False)
        path = fw_module.get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "firewalls": [
                        {"name": "pano", "host": "10.0.0.1"},
                        {"name": "edge", "serial": "00112233", "via": "pano"},
                    ]
                }
            )
        )
        # pano still needs a key; give it one via env-less plaintext fallback.
        # Simplest: only assert the serial entry resolves without a key.
        load_firewall_config()
        edge = resolve_firewall("edge")
        assert edge is not None
        assert edge.is_proxy is True
        assert edge.serial == "00112233"
        assert edge.via == "pano"
        assert edge.api_key is None

    def test_list_entries_marks_serial(self) -> None:
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        _seed(FirewallEntry(name="edge", serial="00112233", via="pano"))
        listed = {e["name"]: e for e in list_firewall_entries()}
        assert listed["pano"] == {"name": "pano", "host": "10.0.0.1"}
        assert listed["edge"]["connection"] == "panorama-serial"
        assert listed["edge"]["serial"] == "00112233"
        assert listed["edge"]["via"] == "pano"
        # Never leaks keys.
        assert "api_key" not in str(listed)


# --- Explicit serial-proxy entry --------------------------------------------


class TestConfiguredSerialEntry:
    def test_gate_off_returns_helpful_error(self) -> None:
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        _seed(FirewallEntry(name="edge", serial="S1", via="pano"))
        result = get_client("edge", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "PANOS_ALLOW_SERIAL_CONNECTION" in result.message

    def test_gate_on_builds_proxied_firewall(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        _seed(FirewallEntry(name="edge", serial="S1", via="pano"))
        result = get_client("edge", tls=TlsConfig())
        assert isinstance(result, RealFirewall)
        assert result.serial == "S1"
        # Routes through the resolved Panorama.
        assert isinstance(result.panorama(), RealPanorama)
        assert result.panorama().hostname == "10.0.0.1"
        # Per-request timeout applied before the xapi is built.
        assert result.timeout == 60

    def test_via_self_reference_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        _seed(FirewallEntry(name="edge", serial="S1", via="edge"))
        result = get_client("edge", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "itself" in result.message

    def test_via_pointing_at_non_panorama_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.base import PanDevice

        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        monkeypatch.setattr(
            PanDevice,
            "show_system_info",
            lambda self: {"system": {"model": "PA-460", "sw-version": "11.1.0", "serial": "FWSER"}},
        )
        monkeypatch.setattr(
            PanDevice, "refresh_system_info", lambda self: ("11.1.0", "PA-460", "FWSER")
        )
        _seed(FirewallEntry(name="notpano", host="10.0.0.1", api_key="k"))
        _seed(FirewallEntry(name="edge", serial="S1", via="notpano"))
        result = get_client("edge", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "Panorama" in result.message


# --- Dynamic discovery ------------------------------------------------------


def _fake_device_map() -> dict[str, DeviceInfo]:
    up = DeviceInfo(serial="S1", hostname="edge1", connected=True)
    down = DeviceInfo(serial="S2", hostname="edge2", connected=False)
    return {"edge1": up, "S1": up, "edge2": down, "S2": down}


class TestDynamicDiscovery:
    def test_resolves_managed_device_by_hostname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = get_client("edge1", tls=TlsConfig())
        assert isinstance(result, RealFirewall)
        assert result.serial == "S1"

    def test_resolves_managed_device_by_serial(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = get_client("S1", tls=TlsConfig())
        assert isinstance(result, RealFirewall)
        assert result.serial == "S1"

    def test_disconnected_device_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = get_client("edge2", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "disconnected" in result.message

    def test_unknown_device_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = get_client("ghost", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "not found" in result.message or "was not found" in result.message

    def test_discovery_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = get_client("edge1", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "PANOS_ALLOW_SERIAL_CONNECTION" in result.message


class TestDirectBeatsProxy:
    def test_direct_entry_wins_over_managed_device(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.base import PanDevice

        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")

        # edge1 detects as a firewall (direct); pano as a Panorama. Detection
        # reads the model from ``show_system_info``.
        def _detect_info(self: Any) -> dict[str, Any]:
            if getattr(self, "hostname", None) == "10.0.0.9":
                return {
                    "system": {"model": "PA-460", "sw-version": "11.1.0", "serial": "DIRECTSER"}
                }
            return {
                "system": {"model": "Panorama", "sw-version": "11.2.0", "serial": "PANO-SERIAL"}
            }

        def _detect(self: Any) -> tuple[str, str, str]:
            if getattr(self, "hostname", None) == "10.0.0.9":
                return ("11.1.0", "PA-460", "DIRECTSER")
            return ("11.2.0", "Panorama", "PANO-SERIAL")

        monkeypatch.setattr(PanDevice, "show_system_info", _detect_info)
        monkeypatch.setattr(PanDevice, "refresh_system_info", _detect)

        # A device map that would also match "edge1" — must NOT be consulted.
        def _boom(pano: Any) -> dict[str, DeviceInfo]:
            raise AssertionError("device map must not be consulted for a direct entry")

        monkeypatch.setattr(client_module, "_fetch_device_map", _boom)
        _seed(FirewallEntry(name="edge1", host="10.0.0.9", api_key="k"))
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = get_client("edge1", tls=TlsConfig())
        assert isinstance(result, RealFirewall)
        assert result.hostname == "10.0.0.9"
        assert result.serial != "S1"  # not the proxied device


class TestDiscoverManagedDevices:
    def test_returns_deduped_inventory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        devices = discover_managed_devices(tls=TlsConfig())
        by_serial = {d["serial"]: d for d in devices}
        assert set(by_serial) == {"S1", "S2"}
        assert by_serial["S1"]["name"] == "edge1"
        assert by_serial["S1"]["connected"] is True
        assert by_serial["S1"]["reachable_via"] == "panorama-serial"
        assert by_serial["S2"]["connected"] is False

    def test_empty_when_flag_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: _fake_device_map())
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        assert discover_managed_devices(tls=TlsConfig()) == []


# --- Device-map parsing -----------------------------------------------------


class TestDeviceMapParsing:
    def test_parses_element_response(self) -> None:
        xml = """
        <response status="success"><result><devices>
            <entry name="S1"><serial>S1</serial><hostname>edge1</hostname><connected>yes</connected></entry>
            <entry name="S2"><serial>S2</serial><hostname>edge2</hostname><connected>no</connected></entry>
        </devices></result></response>
        """
        rows = list(client_module._iter_device_entries(fromstring(xml)))
        by_serial = {r["serial"]: r for r in rows}
        assert by_serial["S1"]["hostname"] == "edge1"
        assert by_serial["S1"]["connected"] == "yes"
        assert by_serial["S2"]["connected"] == "no"

    def test_fetch_device_map_builds_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        xml = (
            '<response status="success"><result><devices>'
            "<entry name='S1'><serial>S1</serial><hostname>edge1</hostname>"
            "<connected>yes</connected></entry>"
            "</devices></result></response>"
        )

        seen: dict[str, Any] = {}

        class FakePano:
            hostname = "10.0.0.1"

            def op(self, cmd: str, cmd_xml: bool = True) -> Any:
                seen["cmd"] = cmd
                seen["cmd_xml"] = cmd_xml
                return fromstring(xml)

        devices = client_module._fetch_device_map(FakePano())
        assert devices["edge1"].serial == "S1"
        assert devices["S1"].hostname == "edge1"
        assert devices["edge1"].connected is True
        # Regression: the command is already XML, so it must be sent verbatim
        # (cmd_xml=False). Under pan-os-python's cmd_xml=True default PAN-OS
        # rejects the payload with "Request is not a valid XML".
        assert seen["cmd_xml"] is False

    def test_parses_dict_response(self) -> None:
        parsed = {"devices": {"entry": [{"serial": "S9", "hostname": "h9", "connected": "yes"}]}}
        rows = list(client_module._iter_device_entries(parsed))
        assert rows == [{"serial": "S9", "hostname": "h9", "connected": "yes"}]

    def test_nested_device_entries_are_not_phantom_devices(self) -> None:
        """A device entry nests ``vsys/entry`` and ``plugin_versions/entry``.

        Regression: those nested entries must NOT be parsed as managed devices
        (which surfaced as bogus ``vsys1`` / ``dlp`` rows in ``list_firewalls``).
        Only the direct children of ``<devices>`` are devices.
        """
        xml = """
        <response status="success"><result><devices>
            <entry name="S1">
                <serial>S1</serial><hostname>edge1</hostname><connected>yes</connected>
                <plugin_versions><entry name="dlp"><pkginfo>dlp-5.0.1</pkginfo></entry></plugin_versions>
                <vsys><entry name="vsys1"><display-name>vsys1</display-name></entry></vsys>
            </entry>
        </devices></result></response>
        """
        rows = list(client_module._iter_device_entries(fromstring(xml)))
        serials = {r.get("serial") for r in rows}
        assert serials == {"S1"}
        assert "dlp" not in serials and "vsys1" not in serials


# --- list_firewalls end-to-end ----------------------------------------------


class TestListFirewallsMerge:
    async def _call_list(self) -> dict[str, Any]:
        from mcp.server.fastmcp import FastMCP
        from node804_mcp_toolkit import Mode, ModeGate

        from panos_mcp.tools._common import ToolContext
        from panos_mcp.tools.firewalls import register_firewall_tools

        mcp = FastMCP("test")
        ctx = ToolContext(
            mcp=mcp, gate=ModeGate(mode=Mode.READ, env_var="PANOS_MODE"), tls=TlsConfig()
        )
        register_firewall_tools(ctx)
        tool = (mcp._tool_manager._tools or {}).get("list_firewalls")  # type: ignore[attr-defined]
        assert tool is not None
        return await tool.fn()

    @pytest.mark.asyncio
    async def test_merges_managed_devices_excluding_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANOS_ALLOW_SERIAL_CONNECTION", "true")
        # edge1 is also a configured direct entry — it must NOT be duplicated
        # into managed_devices.
        dmap = _fake_device_map()
        monkeypatch.setattr(client_module, "_fetch_device_map", lambda pano: dmap)
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        _seed(FirewallEntry(name="edge1", host="10.0.0.9", api_key="k"))
        result = await self._call_list()
        assert result["serial_connection"] is True
        managed_names = {d["name"] for d in result["managed_devices"]}
        assert "edge1" not in managed_names  # already a configured entry
        assert "edge2" in managed_names

    @pytest.mark.asyncio
    async def test_no_managed_devices_key_when_flag_off(self) -> None:
        _seed(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))
        result = await self._call_list()
        assert result["serial_connection"] is False
        assert "managed_devices" not in result
