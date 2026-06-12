"""Tests for the 0.1.6 troubleshooting tools.

Covers the diagnostics module (test_*_policy_match, fib-lookup, sessions),
the config diff/pending-changes/revert tools, and rule hit-count tools.

Fakes only at the pan-os-python boundary (``client.op`` / ``client.xapi``),
register the real tools through a real ModeGate, and assert on the XML the
tool builds and the shape of what it returns.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from xml.etree.ElementTree import fromstring

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.admin_ops import register_admin_ops_tools
from panos_mcp.tools.aggregations import register_aggregation_tools
from panos_mcp.tools.diagnostics import _ip_error, _panorama_guard, register_diagnostics_tools
from panos_mcp.tools.utility import register_utility_tools


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


def _seed_firewall(name: str = "fw1") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host="10.0.0.1", api_key="k"))


def _make_ctx(mode: Mode = Mode.READ) -> tuple[ToolContext, FastMCP, ModeGate]:
    mcp = FastMCP("test")
    sink = open_sink({})
    gate = ModeGate(mode=mode, env_var="PANOS_MODE", audit_sink=sink)
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig(), audit_sink=sink), mcp, gate


async def _call(mcp: FastMCP, tool: str, **kwargs: Any) -> Any:
    entry = (mcp._tool_manager._tools or {}).get(tool)  # type: ignore[attr-defined]
    if entry is None:
        raise AssertionError(f"tool '{tool}' not registered")
    return await entry.fn(**kwargs)


def _fake_op_fw(op_return: Any = None) -> type:
    """FakeFw whose ``op`` records calls and returns a fixed value."""

    class FakeFw:
        def __init__(self, **kwargs: Any) -> None:
            self.hostname = kwargs.get("hostname", "10.0.0.1")
            self.xapi = MagicMock()
            self.op_calls: list[tuple[str, dict[str, Any]]] = []

        def op(self, cmd: str, **kwargs: Any) -> Any:
            self.op_calls.append((cmd, kwargs))
            return op_return if op_return is not None else {}

        def add(self, child: Any) -> Any:
            child.parent = self
            return child

    return FakeFw


def _patch_fw(monkeypatch: pytest.MonkeyPatch, fake: type) -> None:
    monkeypatch.setattr(client_module, "Firewall", fake)


# --- Helper unit tests --------------------------------------------------


class TestHelpers:
    def test_ip_error_rejects_non_ip(self) -> None:
        assert _ip_error("source", "not-an-ip", "op") is not None
        assert _ip_error("source", "10.0.0.0/24", "op") is not None  # CIDR not allowed
        assert _ip_error("source", "10.0.0.5", "op") is None
        assert _ip_error("source", "2001:db8::1", "op") is None

    def test_panorama_guard(self) -> None:
        from panos.panorama import Panorama

        assert _panorama_guard(Panorama("pano.example.com"), "get_sessions") is not None
        assert _panorama_guard(object(), "get_sessions") is None


# --- test_security_policy_match -----------------------------------------


class TestSecurityPolicyMatch:
    @pytest.mark.asyncio
    async def test_builds_xml_and_echoes_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"rules": {"entry": {"@_name": "allow-web"}}}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)

        result = await _call(
            mcp,
            "test_security_policy_match",
            source="10.1.1.1",
            destination="8.8.8.8",
            protocol=6,
            destination_port=443,
            application="ssl",
            firewall="fw1",
        )
        cmd = client_module._CLIENTS["fw1"].op_calls[0][0]
        assert "<test><security-policy-match>" in cmd
        assert "<source>10.1.1.1</source>" in cmd
        assert "<destination>8.8.8.8</destination>" in cmd
        assert "<protocol>6</protocol>" in cmd
        assert "<destination-port>443</destination-port>" in cmd
        assert "<application>ssl</application>" in cmd
        assert result["query"]["source"] == "10.1.1.1"
        assert result["query"]["application"] == "ssl"
        assert "matched" in result

    @pytest.mark.asyncio
    async def test_invalid_source_rejected_before_device(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_op_fw())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)

        result = await _call(
            mcp, "test_security_policy_match", source="bogus", destination="8.8.8.8", firewall="fw1"
        )
        assert result["success"] is False
        assert "single IP address" in result["error"]
        assert "fw1" not in client_module._CLIENTS

    def test_registers_at_read_mode(self) -> None:
        ctx, _mcp, gate = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        for t in (
            "test_security_policy_match",
            "test_nat_policy_match",
            "test_routing_fib_lookup",
            "get_sessions",
            "get_session_detail",
        ):
            assert t in enabled


# --- test_routing_fib_lookup --------------------------------------------


class TestFibLookup:
    @pytest.mark.asyncio
    async def test_builds_xml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"interface": "ethernet1/1", "nh": "1.1.1.1"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)

        result = await _call(
            mcp, "test_routing_fib_lookup", ip="8.8.8.8", virtual_router="trust-vr", firewall="fw1"
        )
        cmd = client_module._CLIENTS["fw1"].op_calls[0][0]
        assert "<test><routing><fib-lookup>" in cmd
        assert "<virtual-router>trust-vr</virtual-router>" in cmd
        assert "<ip>8.8.8.8</ip>" in cmd
        assert result["query"]["ip"] == "8.8.8.8"


# --- get_sessions / get_session_detail ----------------------------------


class TestSessions:
    @pytest.mark.asyncio
    async def test_filter_xml_and_nat_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entry = {
            "id": "12345",
            "application": "ssl",
            "state": "ACTIVE",
            "src": "10.1.1.1",
            "dst": "8.8.8.8",
            "dport": "443",
            "proto": "6",
            "nat": "source",
            "xsource": "203.0.113.5",
            "xdport": "443",
            "internal-noise": "drop-me",
        }
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"entry": [entry]}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)

        result = await _call(
            mcp, "get_sessions", source="10.1.1.1", destination_port=443, firewall="fw1"
        )
        cmd = client_module._CLIENTS["fw1"].op_calls[0][0]
        assert "<show><session><all><filter>" in cmd
        assert "<source>10.1.1.1</source>" in cmd
        assert "<destination-port>443</destination-port>" in cmd
        assert result["total"] == 1
        item = result["items"][0]
        # NAT translation kept in lean view; non-whitelisted field dropped.
        assert item["xsource"] == "203.0.113.5"
        assert item["nat"] == "source"
        assert "internal-noise" not in item

    @pytest.mark.asyncio
    async def test_no_filter_lists_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"entry": []}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)

        await _call(mcp, "get_sessions", firewall="fw1")
        cmd = client_module._CLIENTS["fw1"].op_calls[0][0]
        assert cmd == "<show><session><all></all></session></show>"

    @pytest.mark.asyncio
    async def test_session_detail_builds_id_xml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"id": "99", "state": "ACTIVE"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_diagnostics_tools(ctx)

        result = await _call(mcp, "get_session_detail", session_id=99, firewall="fw1")
        cmd = client_module._CLIENTS["fw1"].op_calls[0][0]
        assert cmd == "<show><session><id>99</id></session></show>"
        assert result["state"] == "ACTIVE"


# --- get_pending_changes / get_config_diff / revert_config --------------


class TestConfigDiff:
    @pytest.mark.asyncio
    async def test_pending_changes_uses_cmd_xml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"member": "admin"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        result = await _call(mcp, "get_pending_changes", firewall="fw1")
        cmd, kwargs = client_module._CLIENTS["fw1"].op_calls[0]
        assert cmd == "show config list changes"
        assert kwargs.get("cmd_xml") is True
        assert result["has_pending"] is True

    @pytest.mark.asyncio
    async def test_config_diff_computes_entry_changes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        candidate = (
            "<result><address>"
            "<entry name='keep'><ip-netmask>10.0.0.1/32</ip-netmask></entry>"
            "<entry name='added'><ip-netmask>10.0.0.9/32</ip-netmask></entry>"
            "<entry name='changed'><ip-netmask>10.0.0.2/32</ip-netmask></entry>"
            "</address></result>"
        )
        running = (
            "<result><address>"
            "<entry name='keep'><ip-netmask>10.0.0.1/32</ip-netmask></entry>"
            "<entry name='removed'><ip-netmask>10.0.0.8/32</ip-netmask></entry>"
            "<entry name='changed'><ip-netmask>10.0.0.99/32</ip-netmask></entry>"
            "</address></result>"
        )

        class FakeXapi:
            def __init__(self) -> None:
                self.element_result: Any = None

            def get(self, xpath: str | None = None) -> None:
                self.element_result = fromstring(candidate)

            def show(self, xpath: str | None = None) -> None:
                self.element_result = fromstring(running)

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "10.0.0.1"
                self.xapi = FakeXapi()

        _patch_fw(monkeypatch, FakeFw)
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        result = await _call(
            mcp,
            "get_config_diff",
            xpath="/config/devices/entry/vsys/entry/address",
            firewall="fw1",
        )
        assert result["identical"] is False
        assert result["added"] == ["added"]
        assert result["removed"] == ["removed"]
        assert result["modified"] == ["changed"]

    @pytest.mark.asyncio
    async def test_config_diff_refuses_protected_subtree(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_op_fw())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        result = await _call(
            mcp, "get_config_diff", xpath="/config/mgt-config/users", firewall="fw1"
        )
        assert result["success"] is False
        assert "protected subtree" in result["error"]
        assert "fw1" not in client_module._CLIENTS

    @pytest.mark.asyncio
    async def test_revert_config_admin_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Not registered below ADMIN.
        ctx, _mcp, gate = _make_ctx(Mode.FULL)
        register_admin_ops_tools(ctx)
        assert "revert_config" not in set(gate.summary()["enabled_tools"])

        # Registered + functional at ADMIN.
        _patch_fw(monkeypatch, _fake_op_fw(op_return={"status": "ok"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.ADMIN)
        register_admin_ops_tools(ctx)
        result = await _call(mcp, "revert_config", firewall="fw1")
        cmd, kwargs = client_module._CLIENTS["fw1"].op_calls[0]
        assert cmd == "revert config"
        assert kwargs.get("cmd_xml") is True
        assert result["success"] is True


# --- get_rule_hit_counts / unused_rules ---------------------------------


def _hit_count_result() -> dict[str, Any]:
    """Shape op_to_dict would produce for ``show rule-hit-count`` (vsys→entry)."""
    return {
        "rule-hit-count": {
            "vsys": {
                "entry": {
                    "@_name": "vsys1",
                    "rule-base": {
                        "entry": {
                            "@_name": "security",
                            "rules": {
                                "entry": [
                                    {
                                        "@_name": "busy-rule",
                                        "hit-count": "517",
                                        "last-hit-timestamp": "1700000000",
                                        "rule-creation-timestamp": "1600000000",
                                    },
                                    {
                                        "@_name": "dead-rule",
                                        "hit-count": "0",
                                        "last-hit-timestamp": "0",
                                        "last-reset-timestamp": "0",
                                        "rule-creation-timestamp": "1500000000",
                                    },
                                ]
                            },
                        }
                    },
                }
            }
        }
    }


def _hit_count_fw(rules_disabled: dict[str, str] | None = None) -> type:
    """FakeFw that returns hit-count data via op and a security rulebase via refreshall."""
    rules_disabled = rules_disabled or {}

    class FakeFw:
        def __init__(self, **kwargs: Any) -> None:
            self.hostname = "10.0.0.1"
            self.xapi = MagicMock()
            self.op_calls: list[tuple[str, dict[str, Any]]] = []

        def op(self, cmd: str, **kwargs: Any) -> Any:
            self.op_calls.append((cmd, kwargs))
            return _hit_count_result()

        def add(self, child: Any) -> Any:
            child.parent = self
            return child

    return FakeFw


class TestHitCounts:
    @pytest.mark.asyncio
    async def test_get_rule_hit_counts_lean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _hit_count_fw())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_aggregation_tools(ctx)

        result = await _call(mcp, "get_rule_hit_counts", firewall="fw1")
        cmd = client_module._CLIENTS["fw1"].op_calls[0][0]
        assert "<show><rule-hit-count>" in cmd
        assert "name='security'" in cmd
        assert result["total"] == 2
        busy = next(i for i in result["items"] if i["name"] == "busy-rule")
        assert busy["hit_count"] == 517
        assert busy["last_hit"] == 1700000000
        # Lean view excludes creation timestamp.
        assert "rule_created" not in busy

    @pytest.mark.asyncio
    async def test_get_rule_hit_counts_verbose(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _hit_count_fw())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_aggregation_tools(ctx)

        result = await _call(mcp, "get_rule_hit_counts", firewall="fw1", verbose=True)
        busy = next(i for i in result["items"] if i["name"] == "busy-rule")
        assert busy["rule_created"] == 1600000000

    @pytest.mark.asyncio
    async def test_unused_rules_filters_zero_hits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Patch SecurityRule.refreshall so the disabled-join returns no rules
        # (both candidate rules treated as enabled).
        monkeypatch.setattr(
            "panos_mcp.tools.aggregations.SecurityRule.refreshall",
            staticmethod(lambda rb: []),
        )
        _patch_fw(monkeypatch, _hit_count_fw())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_aggregation_tools(ctx)

        result = await _call(mcp, "unused_rules", firewall="fw1")
        assert result["total_rules"] == 2
        assert result["unused_count"] == 1
        assert result["unused"][0]["name"] == "dead-rule"
        assert result["unused"][0]["hit_count"] == 0
        assert result["unused"][0]["disabled"] is False


__all__: list[str] = []
