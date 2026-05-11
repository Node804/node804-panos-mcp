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
from mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
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
    fw_module._entries = []
    reset_client_cache()
    yield
    fw_module._entries = []
    reset_client_cache()
    from panos.firewall import Firewall as RealFirewall
    client_module.Firewall = RealFirewall


def _seed_firewall(name: str = "fw1") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host="10.0.0.1", api_key="k"))


def _make_ctx(mode: Mode = Mode.ADMIN) -> tuple[ToolContext, FastMCP, ModeGate]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=mode, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp, gate


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

        def op(self, cmd: str) -> Any:
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
    async def test_passes_description_and_partial_admin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class())
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        await _call(
            mcp, "commit",
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
    async def test_push_calls_commit_all_with_devicegroup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_fw_class(commit_all_return={"id": "777"}))
        _seed_firewall()
        ctx, mcp, _ = _make_ctx()
        register_admin_ops_tools(ctx)

        result = await _call(
            mcp, "panorama_push_to_devices",
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
            mcp, "set_config",
            xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address",
            element="<entry name=\"x\"><ip-netmask>10.0.0.1/32</ip-netmask></entry>",
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
            mcp, "delete_config",
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
            mcp, "run_op_command",
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
        assert elapsed < 0.35, f"calls appear sequential ({elapsed:.2f}s); run_blocking should parallelize"
