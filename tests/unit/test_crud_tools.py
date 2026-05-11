"""Tests for Phase 4 object/tag CRUD tools.

Coverage focus:
  - Mode gating: CRUD tools register only when mode >= STANDARD
  - Success path: pan-os-python create/delete called, success response returned
  - Error path: PanDeviceError captured into {"error": ...} response
  - Input validation: PanosName regex rejects unsafe characters
  - Resolve error: unconfigured firewall returns clean error string
"""

from __future__ import annotations

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


def _seed_firewall(name: str = "fw1") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host="10.0.0.1", api_key="k"))


def _make_ctx_with_mode(mode: Mode = Mode.STANDARD) -> tuple[ToolContext, FastMCP, ModeGate]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=mode, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp, gate


def _patch_fw(monkeypatch: pytest.MonkeyPatch, fake: Any) -> None:
    monkeypatch.setattr(client_module, "Firewall", fake)


async def _call(mcp: FastMCP, tool: str, **kwargs: Any) -> Any:
    """Invoke a registered tool's handler. ``tool`` is the registered tool name.

    Named ``tool`` (not ``name``) so callers can pass ``name="..."`` as a kwarg
    to the underlying PAN-OS tool without colliding with this helper's signature.
    """
    entry = (mcp._tool_manager._tools or {}).get(tool)  # type: ignore[attr-defined]
    if entry is None:
        raise AssertionError(f"tool '{tool}' not registered")
    return await entry.fn(**kwargs)


def _fake_firewall_class() -> type:
    """Build a FakeFw class that records added objects and has a no-op .add()."""

    class FakeFw:
        def __init__(self, **kwargs: Any) -> None:
            self.hostname = kwargs.get("hostname", "10.0.0.1")
            self.added: list[Any] = []

        def add(self, child: Any) -> Any:
            child.parent = self
            self.added.append(child)
            return child

    return FakeFw


# --- Mode gating ----------------------------------------------------------


class TestModeGating:
    """CRUD tools must NOT register when mode < STANDARD."""

    def test_read_mode_blocks_crud_tools(self) -> None:
        ctx, _mcp, gate = _make_ctx_with_mode(Mode.READ)
        register_objects_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        # Reads available
        assert "get_address_objects" in enabled
        # Writes blocked
        assert "add_address_object" not in enabled
        assert "delete_address_object" not in enabled
        assert "add_tag" not in enabled

    def test_standard_mode_enables_crud_tools(self) -> None:
        ctx, _mcp, gate = _make_ctx_with_mode(Mode.STANDARD)
        register_objects_tools(ctx)
        enabled = set(gate.summary()["enabled_tools"])
        # All 10 CRUD tools registered
        for tool_name in [
            "add_address_object",
            "delete_address_object",
            "add_address_group",
            "delete_address_group",
            "add_service_object",
            "delete_service_object",
            "add_service_group",
            "delete_service_group",
            "add_tag",
            "delete_tag",
        ]:
            assert tool_name in enabled, f"{tool_name} should be registered in STANDARD mode"


# --- Success paths --------------------------------------------------------


class TestAddAddressObject:
    @pytest.mark.asyncio
    async def test_create_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_firewall_class())
        # Capture .create() calls on the AddressObject instance
        from panos.objects import AddressObject
        create_mock = MagicMock(return_value=None)
        monkeypatch.setattr(AddressObject, "create", create_mock)

        _seed_firewall()
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)

        result = await _call(
            mcp,
            "add_address_object",
            name="web-srv",
            value="10.0.0.1/32",
            type="ip-netmask",
            firewall="fw1",
        )
        assert result == {"success": True, "operation": "created", "name": "web-srv"}
        assert create_mock.called

    @pytest.mark.asyncio
    async def test_panos_error_returns_error_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_firewall_class())
        from panos.objects import AddressObject
        monkeypatch.setattr(
            AddressObject, "create",
            MagicMock(side_effect=PanDeviceError("Object name already exists")),
        )

        _seed_firewall()
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)

        result = await _call(
            mcp,
            "add_address_object",
            name="web-srv",
            value="10.0.0.1/32",
            firewall="fw1",
        )
        assert result["success"] is False
        assert result["operation"] == "create"
        assert "already exists" in result["error"]


class TestDeleteAddressObject:
    @pytest.mark.asyncio
    async def test_delete_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_firewall_class())
        from panos.objects import AddressObject
        monkeypatch.setattr(AddressObject, "delete", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)

        result = await _call(mcp, "delete_address_object", name="web-srv", firewall="fw1")
        assert result == {"success": True, "operation": "deleted", "name": "web-srv"}


class TestAddTag:
    @pytest.mark.asyncio
    async def test_create_with_color_and_comments(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_firewall_class())
        from panos.objects import Tag
        captured: dict[str, Any] = {}
        original_init = Tag.__init__

        def spy_init(self: Any, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)
            original_init(self, *args, **kwargs)

        monkeypatch.setattr(Tag, "__init__", spy_init)
        monkeypatch.setattr(Tag, "create", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)

        result = await _call(
            mcp,
            "add_tag",
            name="compliance",
            color="color1",
            comments="SecOps approved",
            firewall="fw1",
        )
        assert result == {"success": True, "operation": "created", "name": "compliance"}
        assert captured["color"] == "color1"
        assert captured["comments"] == "SecOps approved"


# --- Input validation -----------------------------------------------------


class TestInputValidation:
    """PanosName / PanosTagName regex must reject unsafe characters.

    These unit-test the Pydantic schemas directly via TypeAdapter rather than
    going through FastMCP's tool dispatch, because validation happens at the
    FastMCP transport layer (parsing incoming JSON-RPC) — we'd be testing the
    wrong layer if we called tool.fn(...) directly with bad inputs.
    """

    def test_xpath_injection_attempt_rejected(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools._schemas import PanosName

        adapter = TypeAdapter(PanosName)
        with pytest.raises(ValidationError):
            adapter.validate_python("evil'/inject")

    @pytest.mark.parametrize("bad", [
        "name<x>",
        'name"q',
        "name/slash",
        "name\nnewline",
        "name\twith\ttab",
        "name(paren)",
        "evil'with-quote",
    ])
    def test_special_chars_rejected(self, bad: str) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools._schemas import PanosName

        adapter = TypeAdapter(PanosName)
        with pytest.raises(ValidationError):
            adapter.validate_python(bad)

    @pytest.mark.parametrize("ok", [
        "web-srv",
        "Site_2.lab",
        "object name with spaces",
        "fw-01",
        "a",
        "Multi.Dot.Name",
    ])
    def test_safe_chars_accepted(self, ok: str) -> None:
        from pydantic import TypeAdapter

        from panos_mcp.tools._schemas import PanosName

        adapter = TypeAdapter(PanosName)
        assert adapter.validate_python(ok) == ok

    def test_panos_name_max_length_enforced(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools._schemas import PanosName

        adapter = TypeAdapter(PanosName)
        adapter.validate_python("a" * 63)  # boundary OK
        with pytest.raises(ValidationError):
            adapter.validate_python("a" * 64)

    def test_tag_name_allows_127_chars(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        from panos_mcp.tools._schemas import PanosTagName

        adapter = TypeAdapter(PanosTagName)
        adapter.validate_python("a" * 127)  # boundary OK
        with pytest.raises(ValidationError):
            adapter.validate_python("a" * 128)

    @pytest.mark.asyncio
    async def test_safe_name_drives_successful_create(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Integration: a safe name flows all the way through to create()."""
        _patch_fw(monkeypatch, _fake_firewall_class())
        from panos.objects import AddressObject
        monkeypatch.setattr(AddressObject, "create", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)

        result = await _call(
            mcp, "add_address_object", name="web-srv", value="10.0.0.1/32", firewall="fw1"
        )
        assert result["success"] is True


# --- Resolve errors -------------------------------------------------------


class TestResolveErrors:
    @pytest.mark.asyncio
    async def test_unknown_firewall_returns_error_response(self) -> None:
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)
        result = await _call(
            mcp,
            "add_address_object",
            name="x",
            value="10.0.0.1/32",
            firewall="nonexistent",
        )
        # Resolve errors short-circuit before pan-os-python is touched.
        assert "error" in result
        assert "nonexistent" in result["error"]


# --- Service object validation ------------------------------------------


class TestServiceObjectPortValidation:
    @pytest.mark.asyncio
    async def test_port_range_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fw(monkeypatch, _fake_firewall_class())
        from panos.objects import ServiceObject
        monkeypatch.setattr(ServiceObject, "create", MagicMock(return_value=None))

        _seed_firewall()
        ctx, mcp, _ = _make_ctx_with_mode()
        register_objects_tools(ctx)

        result = await _call(
            mcp,
            "add_service_object",
            name="webrange",
            protocol="tcp",
            destination_port="8000-8080",
            firewall="fw1",
        )
        assert result["success"] is True
