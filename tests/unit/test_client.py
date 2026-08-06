"""Tests for panos_mcp.client — pan-os-python factory and resolve-error handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from node804_mcp_toolkit import TlsConfig

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import ResolveError, get_client, probe_client, reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    # Stub out the two network calls _build_client can make for auto-detection:
    # ``show_system_info`` (the class-neutral model probe) and, for a confirmed
    # firewall, ``refresh_system_info`` (which fully populates the Firewall).
    # Default the probe to a firewall model so unrelated tests get a Firewall.
    from panos.base import PanDevice

    monkeypatch.setattr(
        PanDevice,
        "show_system_info",
        lambda self: {
            "system": {"model": "PA-460", "sw-version": "11.1.0", "serial": "0123456789"}
        },
    )
    monkeypatch.setattr(
        PanDevice,
        "refresh_system_info",
        lambda self: ("11.1.0", "PA-460", "0123456789"),
    )
    fw_module._entries = []
    reset_client_cache()
    yield
    fw_module._entries = []
    reset_client_cache()


def _seed(name: str, host: str, key: str) -> None:
    fw_module._entries.append(FirewallEntry(name=name, host=host, api_key=key))


class TestGetClient:
    def test_resolve_error_when_unconfigured(self) -> None:
        result = get_client(None, tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "No firewall configured" in result.message

    def test_resolve_error_for_unknown_name(self) -> None:
        _seed("fw1", "10.0.0.1", "k")
        result = get_client("nope", tls=TlsConfig())
        assert isinstance(result, ResolveError)
        assert "'nope'" in result.message
        assert "list_firewalls" in result.message

    def test_constructs_client_for_configured_target(self) -> None:
        _seed("fw1", "10.0.0.1", "k")
        c = get_client("fw1", tls=TlsConfig())
        assert not isinstance(c, ResolveError)
        assert c.hostname == "10.0.0.1"
        # api_key flows into the underlying xapi
        assert c.api_key == "k"

    def test_caches_client_across_calls(self) -> None:
        _seed("fw1", "10.0.0.1", "k")
        c1 = get_client("fw1", tls=TlsConfig())
        c2 = get_client("fw1", tls=TlsConfig())
        assert c1 is c2

    def test_default_resolution_with_single_entry(self) -> None:
        _seed("only", "10.0.0.1", "k")
        c = get_client(None, tls=TlsConfig())
        assert not isinstance(c, ResolveError)
        assert c.hostname == "10.0.0.1"


class TestTlsPlumbing:
    """Verify the TLS config flows into pan-os-python's verify kwarg correctly.

    pan-os-python forwards constructor kwargs to its underlying xapi.PanXapi.
    We don't test the actual TLS handshake (would need a live server); we
    just confirm our factory passes the right kwargs based on TlsConfig.
    """

    def test_default_omits_verify_kwarg(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        class FakeFirewall:
            def __init__(self, **kwargs: Any) -> None:
                captured.update(kwargs)
                self.hostname = kwargs.get("hostname")
                self.api_key = kwargs.get("api_key")

            def show_system_info(self) -> dict[str, Any]:
                return {
                    "system": {
                        "model": "PA-460",
                        "sw-version": "11.1.0",
                        "serial": "0123456789",
                    }
                }

            def refresh_system_info(self) -> tuple[str, str, str]:
                return ("11.1.0", "PA-460", "0123456789")

        monkeypatch.setattr(client_module, "Firewall", FakeFirewall)
        _seed("fw1", "10.0.0.1", "k")
        get_client("fw1", tls=TlsConfig(verify=True))
        assert "verify" not in captured  # use system trust store

    def test_disabled_passes_verify_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        class FakeFirewall:
            def __init__(self, **kwargs: Any) -> None:
                captured.update(kwargs)
                self.hostname = kwargs.get("hostname")
                self.api_key = kwargs.get("api_key")

            def show_system_info(self) -> dict[str, Any]:
                return {
                    "system": {
                        "model": "PA-460",
                        "sw-version": "11.1.0",
                        "serial": "0123456789",
                    }
                }

            def refresh_system_info(self) -> tuple[str, str, str]:
                return ("11.1.0", "PA-460", "0123456789")

        monkeypatch.setattr(client_module, "Firewall", FakeFirewall)
        _seed("fw1", "10.0.0.1", "k")
        get_client("fw1", tls=TlsConfig(verify=False))
        assert captured["verify"] is False

    def test_custom_ca_passes_path_string(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        ca = tmp_path / "ca.pem"
        ca.write_bytes(b"x")
        captured: dict[str, Any] = {}

        class FakeFirewall:
            def __init__(self, **kwargs: Any) -> None:
                captured.update(kwargs)
                self.hostname = kwargs.get("hostname")
                self.api_key = kwargs.get("api_key")

            def show_system_info(self) -> dict[str, Any]:
                return {
                    "system": {
                        "model": "PA-460",
                        "sw-version": "11.1.0",
                        "serial": "0123456789",
                    }
                }

            def refresh_system_info(self) -> tuple[str, str, str]:
                return ("11.1.0", "PA-460", "0123456789")

        monkeypatch.setattr(client_module, "Firewall", FakeFirewall)
        _seed("fw1", "10.0.0.1", "k")
        get_client("fw1", tls=TlsConfig(verify=True, ca_path=ca, ca_bundle=b"x"))
        assert captured["verify"] == str(ca)


class TestAutoDetection:
    """Verify that _build_client returns Panorama when the device model says so."""

    def test_panorama_model_returns_panorama_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from panos.base import PanDevice
        from panos.panorama import Panorama as RealPanorama

        # A Panorama's ``show system info`` has no ``multi-vsys``/``app-version``.
        # The probe must read the model from this dict WITHOUT the Firewall
        # subclass parsing that would raise KeyError on those absent fields.
        monkeypatch.setattr(
            PanDevice,
            "show_system_info",
            lambda self: {"system": {"model": "Panorama", "sw-version": "11.2.0"}},
        )
        _seed("pan1", "10.0.0.1", "k")
        c = get_client("pan1", tls=TlsConfig())
        assert isinstance(c, RealPanorama)

    def test_m_series_model_returns_panorama_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from panos.base import PanDevice
        from panos.panorama import Panorama as RealPanorama

        monkeypatch.setattr(
            PanDevice,
            "show_system_info",
            lambda self: {"system": {"model": "M-200", "sw-version": "11.2.0"}},
        )
        _seed("pan2", "10.0.0.2", "k")
        c = get_client("pan2", tls=TlsConfig())
        assert isinstance(c, RealPanorama)

    def test_panorama_detected_when_firewall_refresh_would_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: a Panorama must be detected via the class-neutral probe.

        The old code probed device type by calling ``refresh_system_info()`` on
        a ``Firewall`` object. ``Firewall._save_system_info`` reads firewall-only
        fields (``multi-vsys``, ``app-version``) that a Panorama's
        ``show system info`` does not return, so that call raised
        ``KeyError: 'multi-vsys'`` *before* the model was inspected — and the
        Panorama was silently cached as a ``Firewall``, breaking every
        ``isinstance(client, Panorama)`` guard. Here ``refresh_system_info`` is
        wired to raise exactly that KeyError; detection must still return a
        Panorama because it reads the model from ``show_system_info`` instead.
        """
        from panos.base import PanDevice
        from panos.panorama import Panorama as RealPanorama

        monkeypatch.setattr(
            PanDevice,
            "show_system_info",
            lambda self: {"system": {"model": "Panorama", "sw-version": "11.2.10-h3"}},
        )

        def _boom(self: Any) -> Any:
            raise KeyError("multi-vsys")

        monkeypatch.setattr(PanDevice, "refresh_system_info", _boom)
        _seed("pan1", "10.0.0.1", "k")
        c = get_client("pan1", tls=TlsConfig())
        assert isinstance(c, RealPanorama)

    def test_firewall_model_returns_firewall_instance(self) -> None:
        from panos.firewall import Firewall as RealFirewall

        _seed("fw1", "10.0.0.1", "k")
        c = get_client("fw1", tls=TlsConfig())
        assert isinstance(c, RealFirewall)

    def test_probe_failure_falls_back_to_firewall(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.base import PanDevice
        from panos.firewall import Firewall as RealFirewall

        monkeypatch.setattr(
            PanDevice,
            "show_system_info",
            lambda self: (_ for _ in ()).throw(ConnectionError("unreachable")),
        )
        _seed("fw1", "10.0.0.1", "k")
        c = get_client("fw1", tls=TlsConfig())
        assert isinstance(c, RealFirewall)


class TestRequestTimeout:
    """A bounded per-request timeout must be applied before the xapi is built.

    pan-os-python defaults to 1200s (20 min) per request and builds the xapi
    lazily from ``client.timeout`` on first use — so the cap has to be set at
    construction or a stuck call hangs the whole MCP process.
    """

    def test_default_timeout_applied_and_propagates_to_xapi(self) -> None:
        _seed("fw1", "10.0.0.1", "k")
        c = get_client("fw1", tls=TlsConfig())
        assert not isinstance(c, ResolveError)
        assert c.timeout == 60
        # Propagation is the part that actually matters — the xapi is what
        # makes the HTTP call, and it only inherits a timeout set before it
        # was built.
        assert c.xapi.timeout == 60

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_API_TIMEOUT", "15")
        _seed("fw1", "10.0.0.1", "k")
        c = get_client("fw1", tls=TlsConfig())
        assert not isinstance(c, ResolveError)
        assert c.timeout == 15
        assert c.xapi.timeout == 15

    def test_invalid_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_API_TIMEOUT", "not-a-number")
        _seed("fw1", "10.0.0.1", "k")
        c = get_client("fw1", tls=TlsConfig())
        assert not isinstance(c, ResolveError)
        assert c.timeout == 60

    def test_panorama_target_also_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.base import PanDevice
        from panos.panorama import Panorama as RealPanorama

        monkeypatch.setattr(
            PanDevice,
            "show_system_info",
            lambda self: {"system": {"model": "Panorama", "sw-version": "11.2.0"}},
        )
        _seed("pan1", "10.0.0.1", "k")
        c = get_client("pan1", tls=TlsConfig())
        assert isinstance(c, RealPanorama)
        assert c.timeout == 60
        assert c.xapi.timeout == 60


class TestProbeClient:
    def test_resolved_target(self) -> None:
        _seed("fw1", "10.0.0.1", "k")
        result = probe_client("fw1", tls=TlsConfig())
        assert result["resolved"] is True
        assert result["host"] == "10.0.0.1"
        assert "Firewall" in result["class"]

    def test_unresolved_target(self) -> None:
        result = probe_client("nope", tls=TlsConfig())
        assert result["resolved"] is False
        assert "'nope'" in result["error"]
