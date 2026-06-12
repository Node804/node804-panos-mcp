"""Tests for panos_mcp.client — pan-os-python factory and resolve-error handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp_toolkit import TlsConfig

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import ResolveError, get_client, probe_client, reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry


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

        monkeypatch.setattr(client_module, "Firewall", FakeFirewall)
        _seed("fw1", "10.0.0.1", "k")
        get_client("fw1", tls=TlsConfig(verify=False))
        assert captured["verify"] is False

    def test_custom_ca_passes_path_string(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        ca = tmp_path / "ca.pem"
        ca.write_bytes(b"x")
        captured: dict[str, Any] = {}

        class FakeFirewall:
            def __init__(self, **kwargs: Any) -> None:
                captured.update(kwargs)
                self.hostname = kwargs.get("hostname")

        monkeypatch.setattr(client_module, "Firewall", FakeFirewall)
        _seed("fw1", "10.0.0.1", "k")
        get_client("fw1", tls=TlsConfig(verify=True, ca_path=ca, ca_bundle=b"x"))
        assert captured["verify"] == str(ca)


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
