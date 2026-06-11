"""Tests for Phase 6 admin tools (commit, push, set_config, run_op_command).

Coverage focus:
  - Mode gating: admin tools register only at Mode.ADMIN
  - Success path: pan-os-python method called via run_blocking (event loop
    stays unblocked), success response returned
  - Error path: PanDeviceError captured into {"error": ...} response
  - Input validation: xpath must start with /config, xml must start with <
  - run_blocking uses the thread executor so a long pan-os-python call
    doesn't block the event loop
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.errors import PanDeviceError

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.admin_ops import register_admin_ops_tools
from panos_mcp.tools.utility import register_utility_tools


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    # Most tests assume the raw-config and raw-op escape hatches are
    # registered.  They're default-off in production but enabling them in
    # tests by default keeps individual cases concise; tests that exercise
    # the gating itself delete the env var locally.
    monkeypatch.setenv("PANOS_ENABLE_RAW_CONFIG", "true")
    monkeypatch.setenv("PANOS_ENABLE_RAW_OPS", "true")
    monkeypatch.delenv("PANOS_RAW_XPATH_ALLOW", raising=False)
    fw_module._entries = []
    reset_client_cache()
    yield
    fw_module._entries = []
    reset_client_cache()
    from panos.firewall import Firewall as RealFirewall

    client_module.Firewall = RealFirewall


def _seed_firewall(name: str = "fw1") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host="10.0.0.1", api_key="k"))


def _make_ctx(
    mode: Mode = Mode.ADMIN,
    *,
    audit_sink: Any = None,
) -> tuple[ToolContext, FastMCP, ModeGate]:
    mcp = FastMCP("test")
    sink = audit_sink if audit_sink is not None else open_sink({})
    gate = ModeGate(mode=mode, env_var="PANOS_MODE", audit_sink=sink)
    return (
        ToolContext(mcp=mcp, gate=gate, tls=TlsConfig(), audit_sink=sink),
        mcp,
        gate,
    )


class _RecordingSink:
    """In-memory audit sink that captures every event for test assertions."""

    enabled = True

    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)

    def describe(self) -> str:
        return "recording"


def _patch_fw(monkeypatch: pytest.MonkeyPatch, fake: Any) -> None:
    monkeypatch.setattr(client_module, "Firewall", fake)


async def _call(mcp: FastMCP, tool: str, **kwargs: Any) -> Any:
    entry = (mcp._tool_manager._tools or {}).get(tool)  # type: ignore[attr-defined]
    if entry is None:
        raise AssertionError(f"tool '{tool}' not registered")
    return await entry.fn(**kwargs)


def _fake_fw_class(
    commit_return: Any = None,
    commit_all_return: Any = None,
    op_return: Any = None,
) -> type:
    """Build a FakeFw whose commit/commit_all/op return the values supplied."""

    class FakeFw:
        def __init__(self, **kwargs: Any) -> None:
            self.hostname = kwargs.get("hostname", "10.0.0.1")
            self.xapi = MagicMock()
            self.commit_calls: list[dict[str, Any]] = []
            self.commit_all_calls: list[dict[str, Any]] = []
            self.op_calls: list[Any] = []

        def commit(self, **kwargs: Any) -> Any:
            self.commit_calls.append(kwargs)
            return commit_return if commit_return is not None else {"id": "42", "status": "PEND"}

        def commit_all(self, **kwargs: Any) -> Any:
            self.commit_all_calls.append(kwargs)
            return commit_all_return if commit_all_return is not None else {"id": "100"}

        def op(self, cmd: str, **kwargs: Any) -> Any:
            self.op_calls.append(cmd)
            return op_return if op_return is not None else {"system": {"hostname": "fw1"}}

        def add(self, child: Any) -> Any:
            child.parent = self
            return child

    return FakeFw


# --- Mode gating ---------------------------------------------------------


class TestModeGating:
    """Admin tools register only at Mode.ADMIN."""

    def test_full_mode_blocks_admin_tools(self) -> None:
        ctx, _mcp, gate = _make_ctx(Mode.FULL)
        register_admin_ops_tools(ctx)
        register_utility_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        # Read utility available
        assert "get_config_xpath" in enabled
        # Admin tools blocked
        for blocked in [
            "commit",
            "panorama_commit",
            "panorama_push_to_devices",
            "set_config",
            "delete_config",
            "run_op_command",
        ]:
            assert blocked not in enabled, f"{blocked} should be blocked in FULL mode"

    def test_admin_mode_enables_all_admin_tools(self) -> None:
        ctx, _mcp, gate = _make_ctx(Mode.ADMIN)
        register_admin_ops_tools(ctx)
        register_utility_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        for required in [
            "commit",
            "panorama_commit",
            "panorama_push_to_devices",
            "set_config",
            "delete_config",
            "run_op_command",
        ]:
            assert required in enabled, f"{required} should register in ADMIN mode"


# --- commit -------------------------------------------------------------


class TestCommit:
    @pytest.mark.asyncio
    async def test_returns_job_id_from_commit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class(commit_return={"id": "1234", "status": "PEND"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(mcp, "commit", description="test commit", firewall="fw1")
        assert result["success"] is True
        assert result["operation"] == "commit"
        assert result["id"] == "1234"

    @pytest.mark.asyncio
    async def test_passes_description_and_partial_admin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        await _call(
            mcp,
            "commit",
            description="Partial commit by SecOps",
            partial_admin="alice",
            firewall="fw1",
        )
        client = client_module._CLIENTS["fw1"]
        kwargs = client.commit_calls[0]
        assert kwargs["description"] == "Partial commit by SecOps"
        assert kwargs["admins"] == ["alice"]
        assert kwargs["sync"] is False

    @pytest.mark.asyncio
    async def test_commit_failure_captured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FailingFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
                self.xapi = MagicMock()

            def commit(self, **kwargs: Any) -> Any:
                raise PanDeviceError("Commit blocked: validation errors")

        _patch_fw(monkeypatch, FailingFw)
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(mcp, "commit", firewall="fw1")
        assert result["success"] is False
        assert "validation errors" in result["error"]


# --- panorama_commit / panorama_push_to_devices ------------------------


class TestPanoramaCommit:
    @pytest.mark.asyncio
    async def test_returns_job_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class(commit_return={"id": "555"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(mcp, "panorama_commit", firewall="fw1")
        assert result["success"] is True
        assert result["id"] == "555"


class TestPanoramaPush:
    @pytest.mark.asyncio
    async def test_push_calls_commit_all_with_devicegroup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class(commit_all_return={"id": "777"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(
            mcp,
            "panorama_push_to_devices",
            device_group="hq-dg",
            description="Push security policy",
            include_template=True,
            firewall="fw1",
        )
        assert result["success"] is True
        assert result["operation"] == "panorama_push"
        assert result["name"] == "hq-dg"
        assert result["id"] == "777"

        client = client_module._CLIENTS["fw1"]
        kwargs = client.commit_all_calls[0]
        assert kwargs["devicegroup"] == "hq-dg"
        assert kwargs["description"] == "Push security policy"
        assert kwargs["include_template"] is True


# --- set_config / delete_config -----------------------------------------


class TestSetConfig:
    @pytest.mark.asyncio
    async def test_calls_xapi_set_with_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(
            mcp,
            "set_config",
            xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address",
            element='<entry name="x"><ip-netmask>10.0.0.1/32</ip-netmask></entry>',
            firewall="fw1",
        )
        assert result["success"] is True
        client = client_module._CLIENTS["fw1"]
        client.xapi.set.assert_called_once()

    def test_xpath_must_start_with_config(self) -> None:
        # Direct schema rejection — FastMCP applies this at transport time.
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools.admin_ops import XPathParam

        with pytest.raises(ValidationError):
            TypeAdapter(XPathParam).validate_python("/wrong/start")

    @pytest.mark.asyncio
    async def test_element_must_start_with_angle(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools.admin_ops import XmlElement

        adapter = TypeAdapter(XmlElement)
        adapter.validate_python("<entry name='x'/>")
        with pytest.raises(ValidationError):
            adapter.validate_python("not xml")


class TestDeleteConfig:
    @pytest.mark.asyncio
    async def test_calls_xapi_delete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(
            mcp,
            "delete_config",
            xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='gone']",
            firewall="fw1",
        )
        assert result["success"] is True
        client = client_module._CLIENTS["fw1"]
        client.xapi.delete.assert_called_once()


# --- run_op_command ----------------------------------------------------


class TestRunOpCommand:
    @pytest.mark.asyncio
    async def test_returns_parsed_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class(op_return={"system": {"hostname": "fw1"}}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_utility_tools(ctx)

        result = await _call(
            mcp,
            "run_op_command",
            command="<show><system><info></info></system></show>",
            firewall="fw1",
        )
        assert result["success"] is True
        assert result["result"]["system"]["hostname"] == "fw1"

    @pytest.mark.asyncio
    async def test_invalid_command_rejected_by_schema(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools.utility import XmlOpCommand

        adapter = TypeAdapter(XmlOpCommand)
        with pytest.raises(ValidationError):
            adapter.validate_python("not xml")


# --- run_show_command (always-registered, Mode.READ) --------------------


class TestRunShowCommand:
    """The read-only counterpart of run_op_command; always registered, no env."""

    @pytest.mark.asyncio
    async def test_show_command_returns_parsed_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class(op_return={"system": {"hostname": "fw1"}}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        result = await _call(
            mcp,
            "run_show_command",
            command="<show><system><info></info></system></show>",
            firewall="fw1",
        )
        assert result["success"] is True
        assert result["result"]["system"]["hostname"] == "fw1"

    def test_show_command_schema_rejects_non_show(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools.utility import XmlShowCommand

        adapter = TypeAdapter(XmlShowCommand)
        # <show ...> accepted
        adapter.validate_python("<show><system><info></info></system></show>")
        for bad in [
            "<request><restart><system></system></restart></request>",
            "<commit></commit>",
            "<clear><session><all></all></session></clear>",
            "not xml",
        ]:
            with pytest.raises(ValidationError):
                adapter.validate_python(bad)

    def test_run_show_command_registers_at_read_mode(self) -> None:
        # Important: even with the env vars unset, run_show_command must
        # be available at the lowest mode.
        ctx, _mcp, gate = _make_ctx(Mode.READ)
        register_utility_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        assert "run_show_command" in enabled

    @pytest.mark.asyncio
    async def test_show_config_of_protected_subtree_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A <show><config> read targeting a secret-bearing subtree is rejected
        # before reaching the device (M2 read denylist).
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        result = await _call(
            mcp,
            "run_show_command",
            command=(
                "<show><config><running><xpath>/config/mgt-config/users"
                "</xpath></running></config></show>"
            ),
            firewall="fw1",
        )
        assert result["success"] is False
        assert "protected subtree" in result["error"]
        # Never hit the device.
        assert client_module._CLIENTS["fw1"].op_calls == []


# --- get_config_xpath: injection + read denylist ------------------------


class TestGetConfigXpathSecurity:
    """H1 (XML/op injection) and M2 (read-side denylist) defenses."""

    def test_xpath_schema_rejects_angle_brackets(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools.utility import XPathParam

        adapter = TypeAdapter(XPathParam)
        # Legitimate xpaths (incl. quoted predicates) are accepted.
        adapter.validate_python("/config/devices/entry[@name='localhost.localdomain']/network")
        # Breakout attempts and non-/config roots are rejected.
        for bad in [
            "/config/x</xpath></running></config></show><request><restart/>",
            "/config/x<foo>",
            "/etc/passwd",
            "config/no-leading-slash",
        ]:
            with pytest.raises(ValidationError):
                adapter.validate_python(bad)

    @pytest.mark.asyncio
    async def test_xpath_value_is_xml_escaped_in_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Even though the schema rejects '<', the command builder escapes the
        # value as defense-in-depth. Verify quotes survive and the wrapper is
        # well-formed for a legitimate predicate xpath.
        _patch_fw(monkeypatch, _fake_fw_class(op_return={"network": {}}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        await _call(
            mcp,
            "get_config_xpath",
            xpath="/config/devices/entry[@name='localhost.localdomain']/network",
            firewall="fw1",
        )
        sent = client_module._CLIENTS["fw1"].op_calls[0]
        assert sent.startswith("<show><config><running><xpath>/config/")
        assert sent.endswith("</xpath></running></config></show>")
        # Quote preserved (valid in XML text), no stray '<' inside the value.
        assert "entry[@name='localhost.localdomain']" in sent

    @pytest.mark.asyncio
    async def test_protected_subtree_read_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx(Mode.READ)
        register_utility_tools(ctx)

        for protected in [
            "/config/shared/certificate",
            "/config/mgt-config/users",
            "/config/shared/authentication-profile",
        ]:
            result = await _call(mcp, "get_config_xpath", xpath=protected, firewall="fw1")
            assert result["success"] is False, protected
            assert "protected subtree" in result["error"]
        # Rejected before the client is even resolved — no device contact.
        assert "fw1" not in client_module._CLIENTS


# --- Security guards: env gating + denylists ----------------------------


class TestRawConfigGating:
    """set_config / delete_config must require PANOS_ENABLE_RAW_CONFIG=true."""

    def test_raw_config_unregistered_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PANOS_ENABLE_RAW_CONFIG", raising=False)
        ctx, _mcp, gate = _make_ctx(Mode.ADMIN)
        register_admin_ops_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        # Other ADMIN tools still register; only the raw escape hatches gate.
        assert "commit" in enabled
        assert "set_config" not in enabled
        assert "delete_config" not in enabled

    def test_raw_config_registered_when_env_true(self) -> None:
        # The autouse fixture sets PANOS_ENABLE_RAW_CONFIG=true.
        ctx, _mcp, gate = _make_ctx(Mode.ADMIN)
        register_admin_ops_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        assert "set_config" in enabled
        assert "delete_config" in enabled

    @pytest.mark.parametrize(
        "denied_xpath",
        [
            "/config/mgt-config/users/entry[@name='attacker']",
            "/config/shared/certificate/entry[@name='trust']",
            "/config/shared/admin-role/entry[@name='superuser']",
            "/config/devices/entry[@name='localhost.localdomain']"
            "/deviceconfig/high-availability/enabled",
        ],
    )
    @pytest.mark.asyncio
    async def test_denylisted_xpath_blocked_on_set(
        self, monkeypatch: pytest.MonkeyPatch, denied_xpath: str
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(
            mcp,
            "set_config",
            xpath=denied_xpath,
            element="<entry name='x'/>",
            firewall="fw1",
        )
        assert result["success"] is False
        assert "protected subtree" in result["error"]
        # Critically: the firewall was never touched.
        client = client_module._CLIENTS["fw1"]
        client.xapi.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_denylisted_xpath_blocked_on_delete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)
        result = await _call(
            mcp,
            "delete_config",
            xpath="/config/mgt-config/users/entry[@name='admin']",
            firewall="fw1",
        )
        assert result["success"] is False
        assert "protected subtree" in result["error"]
        client = client_module._CLIENTS["fw1"]
        client.xapi.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_allowlist_restricts_surface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Operator may further restrict to a single subtree via env.
        monkeypatch.setenv(
            "PANOS_RAW_XPATH_ALLOW",
            "/config/devices/entry[@name='localhost.localdomain']/vsys",
        )
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        # Inside the allowed subtree → succeeds.
        ok = await _call(
            mcp,
            "set_config",
            xpath="/config/devices/entry[@name='localhost.localdomain']"
            "/vsys/entry[@name='vsys1']/address",
            element="<entry name='x'><ip-netmask>1.2.3.4/32</ip-netmask></entry>",
            firewall="fw1",
        )
        assert ok["success"] is True

        # Outside the allowed subtree → rejected even when not denylisted.
        denied = await _call(
            mcp,
            "set_config",
            xpath="/config/devices/entry[@name='localhost.localdomain']/network",
            element="<x/>",
            firewall="fw1",
        )
        assert denied["success"] is False
        assert "allow-list" in denied["error"]


class TestRawOpGating:
    """run_op_command must require PANOS_ENABLE_RAW_OPS=true and apply denylist."""

    def test_run_op_unregistered_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PANOS_ENABLE_RAW_OPS", raising=False)
        ctx, _mcp, gate = _make_ctx(Mode.ADMIN)
        register_utility_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        # run_show_command still registers; only run_op_command gates.
        assert "run_show_command" in enabled
        assert "run_op_command" not in enabled

    def test_run_op_registered_when_env_true(self) -> None:
        ctx, _mcp, gate = _make_ctx(Mode.ADMIN)
        register_utility_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        assert "run_op_command" in enabled

    @pytest.mark.parametrize(
        "denied_cmd",
        [
            "<request><restart><system></system></restart></request>",
            "<request><shutdown><system></system></shutdown></request>",
            "<request><system><private-data-reset></private-data-reset></system></request>",
            "<request><system><software><check></check></software></system></request>",
            "<debug><dataplane><pcap></pcap></dataplane></debug>",
        ],
    )
    @pytest.mark.asyncio
    async def test_denylisted_op_blocked(
        self, monkeypatch: pytest.MonkeyPatch, denied_cmd: str
    ) -> None:
        fake_cls = _fake_fw_class()
        _patch_fw(monkeypatch, fake_cls)
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_utility_tools(ctx)
        result = await _call(mcp, "run_op_command", command=denied_cmd, firewall="fw1")
        assert result["success"] is False
        assert "denied pattern" in result["error"]
        # Firewall was never reached.
        client = client_module._CLIENTS["fw1"]
        assert client.op_calls == []


# --- Pre-flight audit emission (defense-in-depth audit trail) ----------


class TestPreflightAudit:
    """High-impact tools must emit a pre-flight audit record before the
    network call.  This is independent of the toolkit's post-call audit
    and survives kill-9 / network hang scenarios."""

    @pytest.mark.asyncio
    async def test_commit_emits_preflight(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        sink = _RecordingSink()
        ctx, mcp, _ = _make_ctx(audit_sink=sink)
        register_admin_ops_tools(ctx)

        await _call(mcp, "commit", description="hello", firewall="fw1")
        preflights = [e for e in sink.events if e.extra.get("phase") == "preflight"]
        assert len(preflights) == 1
        assert preflights[0].tool == "commit"
        assert preflights[0].args["description"] == "hello"
        assert preflights[0].extra["firewall"] == "fw1"

    @pytest.mark.asyncio
    async def test_set_config_emits_preflight_with_truncated_element(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        sink = _RecordingSink()
        ctx, mcp, _ = _make_ctx(audit_sink=sink)
        register_admin_ops_tools(ctx)

        # Big element body — pre-flight record should truncate it.
        big = "<entry name='x'>" + ("<long/>" * 200) + "</entry>"
        await _call(
            mcp,
            "set_config",
            xpath="/config/devices/entry[@name='localhost.localdomain']"
            "/vsys/entry[@name='vsys1']/address",
            element=big,
            firewall="fw1",
        )
        preflights = [e for e in sink.events if e.extra.get("phase") == "preflight"]
        assert len(preflights) == 1
        head = preflights[0].args["element_head"]
        assert len(head) <= 201  # 200 chars + optional ellipsis
        assert preflights[0].args["element_len"] == len(big)

    @pytest.mark.asyncio
    async def test_blocked_set_config_does_not_emit_preflight(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # If the denylist rejects the call, there's no network operation
        # to audit — and we should NOT emit a preflight (the rejection is
        # already logged to stderr via _guards).  This pins the ordering.
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        sink = _RecordingSink()
        ctx, mcp, _ = _make_ctx(audit_sink=sink)
        register_admin_ops_tools(ctx)

        result = await _call(
            mcp,
            "set_config",
            xpath="/config/mgt-config/users/entry[@name='attacker']",
            element="<entry/>",
            firewall="fw1",
        )
        assert result["success"] is False
        preflights = [e for e in sink.events if e.extra.get("phase") == "preflight"]
        assert preflights == []


# --- Event-loop responsiveness via run_blocking -------------------------


class TestRunBlockingDoesNotStallEventLoop:
    """run_blocking must use a thread executor so the event loop stays free."""

    @pytest.mark.asyncio
    async def test_concurrent_tools_run_in_parallel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate a slow pan-os-python commit. If run_blocking dispatches it
        # to a thread executor, two concurrent calls should overlap.
        class SlowFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
                self.xapi = MagicMock()

            def commit(self, **kwargs: Any) -> Any:
                time.sleep(0.2)  # simulate slow PAN-OS commit
                return {"id": "x"}

        _patch_fw(monkeypatch, SlowFw)
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        start = time.monotonic()
        results = await asyncio.gather(
            _call(mcp, "commit", firewall="fw1"),
            _call(mcp, "commit", firewall="fw1"),
        )
        elapsed = time.monotonic() - start
        assert all(r["success"] for r in results)
        # If sequential (event-loop-blocking): ~0.4s. If parallel via executor:
        # ~0.2s. Allow generous margin for test machines.
        assert elapsed < 0.35, (
            f"calls appear sequential ({elapsed:.2f}s); run_blocking should parallelize"
        )
