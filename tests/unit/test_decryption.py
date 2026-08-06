"""Coverage for the two decryption read paths that pan-os-python can't model.

  - ``get_decryption_profiles`` — ``DecryptionProfile`` isn't in the
    pan-os-python object model in any release, so the tool reads the running
    config via xpath (vsys1 + shared) and merges the two trees.
  - ``panorama_get_pre_rules`` / ``panorama_get_post_rules`` with
    ``rule_type="decryption"`` — the reliable per-DG path for decryption rules
    in a Panorama device group (the bulk walker can stall on large policies).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.errors import PanDeviceError
from panos.panorama import DeviceGroup, Panorama
from panos.policies import (
    DecryptionRule,
    NatRule,
    PolicyBasedForwarding,
    PreRulebase,
    SecurityRule,
)

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.certificates import register_certificates_tools
from panos_mcp.tools.panorama import register_panorama_tools


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


# ── get_decryption_profiles (raw-xpath path) ──────────────────────────────


class _Xapi:
    """Stand-in for pan-os-python's xapi: ``show(xpath=...)`` returns a dict.

    Config xpath reads now go through ``config_xpath_to_dict`` →
    ``client.xapi.show(xpath=...)`` (the xpath API, which handles names with
    spaces), so fakes expose ``xapi.show`` instead of ``op``.
    """

    def __init__(self, show_fn: Any) -> None:
        self._show_fn = show_fn

    def show(self, xpath: str | None = None, **_kw: Any) -> Any:
        return self._show_fn(xpath)


class TestGetDecryptionProfiles:
    @pytest.mark.asyncio
    async def test_merges_vsys_and_shared_normalizing_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """vsys1 + shared profiles are merged and ``@_name`` becomes ``name``."""

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "fw1")
                self.xapi = _Xapi(self._show)

            def _show(self, xpath: str | None) -> dict[str, Any]:
                if "vsys/entry[@name='vsys1']" in (xpath or ""):
                    return {
                        "decryption": {
                            "entry": [
                                {"@_name": "fwd-proxy", "description": "outbound"},
                                {"@_name": "no-decrypt", "description": None},
                            ]
                        }
                    }
                # shared tree — single entry (dict, not list)
                return {"decryption": {"entry": {"@_name": "shared-prof", "description": "sh"}}}

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_profiles", firewall="fw1")

        names = {item["name"] for item in result["items"]}
        assert names == {"fwd-proxy", "no-decrypt", "shared-prof"}
        assert result["total"] == 3

    @pytest.mark.asyncio
    async def test_same_name_in_two_scopes_kept_and_tagged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A name present in vsys and shared yields two rows, tagged by scope.

        These are distinct objects (a firewall's vsys profile shadows a shared
        one of the same name) so the reader surfaces both with their ``scope``
        rather than silently collapsing them.
        """

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"
                self.xapi = _Xapi(self._show)

            def _show(self, xpath: str | None) -> dict[str, Any]:
                if "vsys/entry[@name='vsys1']" in (xpath or ""):
                    return {"decryption": {"entry": {"@_name": "dup", "description": "from-vsys"}}}
                return {"decryption": {"entry": {"@_name": "dup", "description": "from-shared"}}}

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_profiles", firewall="fw1", verbose=True)

        assert result["total"] == 2
        by_scope = {item["scope"]: item["description"] for item in result["items"]}
        assert by_scope == {"vsys1": "from-vsys", "shared": "from-shared"}

    @pytest.mark.asyncio
    async def test_transport_error_surfaces_not_swallowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A connection failure must surface (in ``errors``), not look like 'no profiles'.

        Regression guard: a real failure (not "No such node") is recorded
        per-scope in ``errors`` rather than being mistaken for an empty profile
        set — the rest of the walk continues.
        """

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"
                self.xapi = _Xapi(self._show)

            def _show(self, xpath: str | None) -> dict[str, Any]:
                raise PanDeviceError("Timeout waiting for response from device")

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_profiles", firewall="fw1")

        assert result["total"] == 0
        assert "errors" in result
        # Both firewall scopes (vsys1, shared) failed and are recorded.
        assert {e["scope"] for e in result["errors"]} == {"vsys1", "shared"}
        assert any("Timeout" in e["error"] for e in result["errors"])

    @pytest.mark.asyncio
    async def test_hanging_fetch_times_out_and_is_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fetch that never returns is bounded, skipped, and listed in ``timed_out``.

        Regression guard: the call must not sit until the client-level request
        timeout — the per-fetch asyncio timeout bounds it. We set the bound to
        a fraction of a second and have ``op`` block, so the test is fast.
        """
        import threading

        monkeypatch.setenv("PANOS_PROFILE_FETCH_TIMEOUT", "0.2")
        release = threading.Event()

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"
                self.xapi = _Xapi(self._show)

            def _show(self, xpath: str | None) -> dict[str, Any]:
                # Block as a stuck device would; released after the test asserts.
                release.wait(timeout=10)
                return {"decryption": {"entry": {"@_name": "too-late"}}}

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        try:
            result = await _call(mcp, "get_decryption_profiles", firewall="fw1")
        finally:
            release.set()  # let the orphaned worker thread exit

        assert result["total"] == 0
        # Both firewall scopes blocked → both skipped and recorded.
        assert set(result["timed_out"]) == {"vsys1", "shared"}

    @pytest.mark.asyncio
    async def test_no_such_node_is_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A ``PanDeviceError`` on one tree doesn't sink the whole call."""

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"
                self.xapi = _Xapi(self._show)

            def _show(self, xpath: str | None) -> dict[str, Any]:
                if "vsys/entry[@name='vsys1']" in (xpath or ""):
                    return {"decryption": {"entry": {"@_name": "only-vsys"}}}
                raise PanDeviceError("No such node")

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_profiles", firewall="fw1")

        assert result["total"] == 1
        assert result["items"][0]["name"] == "only-vsys"

    @pytest.mark.asyncio
    async def test_decryption_rules_on_panorama_redirects_to_sibling(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """get_decryption_rules against a Panorama must redirect, not return empty.

        The firewall-local rulebase is empty on a Panorama, so a silent empty
        result reads as 'no SSL decryption configured' — a dangerously wrong
        audit. The tool returns an error naming the correct per-DG tools.
        """
        pano = Panorama("h", "u", "p")
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_rules")

        assert "error" in result
        assert result["total"] == 0
        # Steers the agent to the right tool by name.
        assert "panorama_get_pre_rules" in result["error"]
        assert "rule_type='decryption'" in result["error"]

    @pytest.mark.asyncio
    async def test_decryption_rules_on_firewall_still_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On a firewall target the redirect must NOT fire — normal read proceeds."""

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = "fw1"

            def add(self, _child: Any) -> None:  # Rulebase attach is a no-op here
                pass

        monkeypatch.setattr(client_module, "Firewall", FakeFw)
        fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))
        monkeypatch.setattr(
            "panos.policies.DecryptionRule.refreshall",
            staticmethod(lambda *a, **k: [_FakeObj(name="ssl-fwd", action="decrypt")]),
        )
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_rules", firewall="fw1")

        assert "error" not in result
        assert result["items"][0]["name"] == "ssl-fwd"

    @pytest.mark.asyncio
    async def test_panorama_walks_shared_and_device_groups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On a Panorama, profiles are read from shared + every device group, scope-tagged.

        This is the core fix: the old reader only checked shared + the
        firewall-vsys path and returned empty on a Panorama whose device groups
        held the profiles.
        """
        pano = Panorama("h", "u", "p")
        dgs = [DeviceGroup("DG-A"), DeviceGroup("DG-B"), DeviceGroup("DG-empty")]
        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)

        def _show(xpath: str | None) -> dict[str, Any]:
            xpath = xpath or ""
            if "device-group/entry[@name='DG-A']" in xpath:
                return {"decryption": {"entry": {"@_name": "fwd-proxy-A"}}}
            if "device-group/entry[@name='DG-B']" in xpath:
                return {
                    "decryption": {
                        "entry": [{"@_name": "fwd-proxy-B"}, {"@_name": "inbound-B"}]
                    }
                }
            # shared and DG-empty have nothing.
            raise PanDeviceError("No such node")

        monkeypatch.setattr(
            "panos_mcp.tools.certificates.config_xpath_to_dict",
            lambda _client, xpath: _show(xpath),
        )
        ctx, mcp = _make_ctx()
        register_certificates_tools(ctx)

        result = await _call(mcp, "get_decryption_profiles")

        # The firewall-vsys path is NOT queried on a Panorama; profiles come
        # from the device groups, each tagged with its source scope.
        by_name = {i["name"]: i["scope"] for i in result["items"]}
        assert by_name == {
            "fwd-proxy-A": "DG-A",
            "fwd-proxy-B": "DG-B",
            "inbound-B": "DG-B",
        }
        assert result["total"] == 3


# ── panorama_get_pre_rules / post_rules with rule_type ────────────────────


def _wire_panorama(
    monkeypatch: pytest.MonkeyPatch,
    *,
    device_groups: list[str],
    rules_by_parent: dict[tuple[type, str, str], list[Any]],
) -> Panorama:
    pano = Panorama("h", "u", "p")
    dgs = [DeviceGroup(name) for name in device_groups]
    monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
    monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))

    def _dispatch(cls: type) -> staticmethod:
        def _refresh(parent: Any, *_a: Any, **_kw: Any) -> list[Any]:
            grandparent = parent.parent
            dg_name = grandparent.name if isinstance(grandparent, DeviceGroup) else "<shared>"
            rb_label = "pre" if isinstance(parent, PreRulebase) else "post"
            return rules_by_parent.get((cls, dg_name, rb_label), [])

        return staticmethod(_refresh)

    for cls in (SecurityRule, NatRule, PolicyBasedForwarding, DecryptionRule):
        monkeypatch.setattr(cls, "refreshall", _dispatch(cls))
    return pano


class _FakeObj:
    def __init__(self, **data: Any) -> None:
        self._data = data
        self.name = data.get("name")

    def about(self) -> dict[str, Any]:
        return dict(self._data)


class TestPerDeviceGroupRuleType:
    @pytest.mark.asyncio
    async def test_pre_rules_decryption_reads_decryption_rulebase(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["dg"],
            rules_by_parent={
                (DecryptionRule, "dg", "pre"): [
                    _FakeObj(name="ssl-fwd", action="decrypt", type="ssl-forward-proxy"),
                ],
                (SecurityRule, "dg", "pre"): [_FakeObj(name="sec-1", action="allow")],
            },
        )
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp, "panorama_get_pre_rules", device_group="dg", rule_type="decryption"
        )

        assert result["total"] == 1
        assert result["items"][0]["name"] == "ssl-fwd"
        assert result["items"][0]["action"] == "decrypt"

    @pytest.mark.asyncio
    async def test_post_rules_decryption(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["dg"],
            rules_by_parent={
                (DecryptionRule, "dg", "post"): [_FakeObj(name="ssh-proxy", action="no-decrypt")],
            },
        )
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp, "panorama_get_post_rules", device_group="dg", rule_type="decryption"
        )

        assert result["total"] == 1
        assert result["items"][0]["name"] == "ssh-proxy"

    @pytest.mark.asyncio
    async def test_default_rule_type_is_security(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Omitting rule_type preserves the original security-rule behavior."""
        _wire_panorama(
            monkeypatch,
            device_groups=["dg"],
            rules_by_parent={
                (SecurityRule, "dg", "pre"): [
                    _FakeObj(name="sec-1", action="allow", group="best-practice"),
                ],
                (DecryptionRule, "dg", "pre"): [_FakeObj(name="should-not-appear")],
            },
        )
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(mcp, "panorama_get_pre_rules", device_group="dg")

        assert result["total"] == 1
        assert result["items"][0]["name"] == "sec-1"
        # Security-rule enrichment still runs on the default path.
        assert result["items"][0]["has_inspection"] is True

    @pytest.mark.asyncio
    async def test_missing_device_group_returns_clean_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(monkeypatch, device_groups=["dg"], rules_by_parent={})
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp, "panorama_get_pre_rules", device_group="nope", rule_type="decryption"
        )

        assert "error" in result
        assert "nope" in result["error"]

    @pytest.mark.asyncio
    async def test_decryption_read_is_bounded_not_hanging(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stuck DecryptionRule.refreshall must time out cleanly, never hang.

        Regression guard for the reported per-DG decryption hang: the rulebase
        read runs off-loop under the bounded read timeout (identical treatment
        to panorama_walk_all_rules). We make the decryption refreshall block and
        set the bound to a fraction of a second, so the test is fast.
        """
        import threading

        from panos.panorama import DeviceGroup, Panorama
        from panos.policies import DecryptionRule

        monkeypatch.setenv("PANOS_READ_TIMEOUT", "0.2")
        release = threading.Event()
        pano = Panorama("h", "u", "p")
        dgs = [DeviceGroup("Internet-FWs")]
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))

        def _stuck(parent: Any, *_a: Any, **_k: Any) -> list[Any]:
            release.wait(timeout=10)  # never-answering device
            return []

        monkeypatch.setattr(DecryptionRule, "refreshall", staticmethod(_stuck))
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        try:
            result = await _call(
                mcp,
                "panorama_get_post_rules",
                device_group="Internet-FWs",
                rule_type="decryption",
            )
        finally:
            release.set()

        assert "error" in result
        assert "timed out" in result["error"].lower()
        assert result["total"] == 0


# ── Device-group / shared object readers ──────────────────────────────────


def _wire_panorama_objects(
    monkeypatch: pytest.MonkeyPatch,
    *,
    device_groups: list[str],
    objects_by_parent: dict[tuple[type, str], list[Any]],
) -> Panorama:
    """Route ``cls.refreshall(parent)`` by (cls, dg_name|'<shared>').

    A DeviceGroup parent keys on its name; a Panorama parent keys on
    '<shared>'. Missing keys → empty list.
    """
    from panos.objects import (
        AddressGroup,
        AddressObject,
        ApplicationFilter,
        SecurityProfileGroup,
        ServiceGroup,
        ServiceObject,
        Tag,
    )

    pano = Panorama("h", "u", "p")
    dgs = [DeviceGroup(name) for name in device_groups]
    monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
    monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))

    def _dispatch(cls: type) -> staticmethod:
        def _refresh(parent: Any, *_a: Any, **_kw: Any) -> list[Any]:
            key = parent.name if isinstance(parent, DeviceGroup) else "<shared>"
            return objects_by_parent.get((cls, key), [])

        return staticmethod(_refresh)

    for cls in (
        AddressObject,
        AddressGroup,
        ServiceObject,
        ServiceGroup,
        ApplicationFilter,
        SecurityProfileGroup,
        Tag,
    ):
        monkeypatch.setattr(cls, "refreshall", _dispatch(cls))
    return pano


class TestPanoramaObjectReaders:
    @pytest.mark.asyncio
    async def test_device_group_address_objects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.objects import AddressObject

        _wire_panorama_objects(
            monkeypatch,
            device_groups=["dg"],
            objects_by_parent={
                (AddressObject, "dg"): [
                    _FakeObj(name="web-srv", value="10.0.0.5/32"),
                    _FakeObj(name="db-srv", value="10.0.0.6/32"),
                ],
                (AddressObject, "<shared>"): [_FakeObj(name="shared-only")],
            },
        )
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp, "panorama_get_device_group_address_objects", device_group="dg"
        )

        names = {i["name"] for i in result["items"]}
        assert names == {"web-srv", "db-srv"}  # shared-only NOT included

    @pytest.mark.asyncio
    async def test_shared_tags_read_panorama_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.objects import Tag

        _wire_panorama_objects(
            monkeypatch,
            device_groups=["dg"],
            objects_by_parent={
                (Tag, "<shared>"): [_FakeObj(name="prod"), _FakeObj(name="dmz")],
                (Tag, "dg"): [_FakeObj(name="should-not-appear")],
            },
        )
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(mcp, "panorama_get_shared_tags")

        names = {i["name"] for i in result["items"]}
        assert names == {"prod", "dmz"}

    @pytest.mark.asyncio
    async def test_device_group_objects_missing_dg_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama_objects(monkeypatch, device_groups=["dg"], objects_by_parent={})
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp, "panorama_get_device_group_service_objects", device_group="ghost"
        )

        assert "error" in result
        assert "ghost" in result["error"]


class TestPanoramaAdminRoles:
    @pytest.mark.asyncio
    async def test_reads_panorama_level_admin_role_tree(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pano = Panorama("h", "u", "p")

        def _show(xpath: str | None) -> dict[str, Any]:
            # Panorama admin roles live at the device-level admin-role tree.
            assert xpath is not None and "/admin-role" in xpath
            assert "vsys" not in xpath  # not the per-firewall vsys1 path
            return {
                "admin-role": {
                    "entry": [
                        {"@_name": "read-only-noc", "role": {"custom": {}}},
                        {"@_name": "audit"},
                    ]
                }
            }

        monkeypatch.setattr(
            "panos_mcp.tools.panorama.config_xpath_to_dict",
            lambda _client, xpath: _show(xpath),
        )
        monkeypatch.setattr("panos_mcp.tools._common.get_client", lambda *a, **k: pano)
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(mcp, "panorama_get_admin_roles")

        assert result["total"] == 2
