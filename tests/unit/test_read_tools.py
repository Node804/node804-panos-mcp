"""End-to-end tests for representative Phase 3 read tools.

We verify the full pipeline (resolve → pan-os-python call → shape → return)
against mock pan-os-python clients. Per category we test one tool that
exercises an op-command path and one that exercises the .refreshall path.
That gives confidence the patterns work without testing all 71 tools
individually.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink

import panos_mcp.client as client_module
import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
from panos_mcp.tools.objects import register_objects_tools
from panos_mcp.tools.security import register_security_tools
from panos_mcp.tools.system import register_system_tools

# --- Test fixtures ---------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    fw_module._entries = []
    reset_client_cache()  # otherwise a Firewall from one test bleeds into the next
    yield
    fw_module._entries = []
    reset_client_cache()
    # Restore the real Firewall class in case a test patched it.
    from panos.firewall import Firewall as RealFirewall
    client_module.Firewall = RealFirewall


def _seed_firewall(name: str = "fw1", host: str = "10.0.0.1", key: str = "k") -> None:
    fw_module._entries.append(FirewallEntry(name=name, host=host, api_key=key))


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


def _patch_firewall_class(monkeypatch: pytest.MonkeyPatch, fake_class: Any) -> None:
    """Replace pan-os-python's Firewall constructor with a fake.

    The :func:`get_client` factory imports Firewall from panos.firewall, so
    we patch the symbol re-exported in our client module.
    """
    import panos_mcp.client as client_module
    monkeypatch.setattr(client_module, "Firewall", fake_class)


async def _call(mcp: FastMCP, name: str, **kwargs: Any) -> Any:
    tool = (mcp._tool_manager._tools or {}).get(name)  # type: ignore[attr-defined]
    if tool is None:
        raise AssertionError(f"tool '{name}' not registered")
    return await tool.fn(**kwargs)


# --- get_firewall_info (op-command path) ----------------------------------


class TestGetFirewallInfo:
    @pytest.mark.asyncio
    async def test_returns_lean_default_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeFw:
            hostname = "10.0.0.1"
            api_key = "k"
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "10.0.0.1")

            def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
                # op_to_dict accepts a dict directly when our converter sees one.
                return {"system": {
                    "hostname": "fw1",
                    "model": "PA-220",
                    "serial": "00112233",
                    "sw-version": "11.1.0",
                    "uptime": "5 days",
                    "ip-address": "10.0.0.1",
                    "multi-vsys": "no",
                    # Verbose-only fields:
                    "av-version": "4321-1234",
                    "platform-family": "pa-200",
                    "device-certificate-status": "Valid",
                }}

        _patch_firewall_class(monkeypatch, FakeFw)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)

        result = await _call(mcp, "get_firewall_info", firewall="fw1")

        assert result["hostname"] == "fw1"
        assert result["model"] == "PA-220"
        # Verbose-only fields excluded by default
        assert "av-version" not in result
        assert "platform-family" not in result

    @pytest.mark.asyncio
    async def test_verbose_includes_all_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")

            def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
                return {"system": {"hostname": "fw1", "av-version": "4321-1234"}}

        _patch_firewall_class(monkeypatch, FakeFw)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)

        result = await _call(mcp, "get_firewall_info", firewall="fw1", verbose=True)
        assert result["hostname"] == "fw1"
        assert result["av-version"] == "4321-1234"

    @pytest.mark.asyncio
    async def test_unresolved_firewall_returns_error(self) -> None:
        ctx, mcp = _make_ctx()
        register_system_tools(ctx)
        result = await _call(mcp, "get_firewall_info", firewall="nonexistent")
        assert "error" in result
        assert "nonexistent" in result["error"]


# --- get_address_objects (refreshall path) --------------------------------


class TestGetAddressObjects:
    @pytest.mark.asyncio
    async def test_returns_paginated_lean_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Build 150 fake address objects to test pagination.
        class FakeAddr:
            def __init__(self, name: str) -> None:
                self.name = name
                self._data = {
                    "name": name,
                    "ip_netmask": "10.0.0.1/32",
                    "description": None,
                    "tag": ["a-tag"],
                    "uuid": "internal-uuid",
                }

            def about(self) -> dict[str, Any]:
                return self._data

        fake_objects = [FakeAddr(f"addr-{i}") for i in range(150)]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")

        # Patch refreshall to return our fake objects regardless of arguments.
        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.objects import AddressObject
        monkeypatch.setattr(AddressObject, "refreshall", staticmethod(lambda *a, **k: fake_objects))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        # Default pagination = limit 100, offset 0
        result = await _call(mcp, "get_address_objects", firewall="fw1")
        assert result["total"] == 150
        assert result["count"] == 100
        assert result["items"][0]["name"] == "addr-0"
        # Lean view drops description (None) and uuid (not in default_fields).
        assert "description" not in result["items"][0]
        assert "uuid" not in result["items"][0]

    @pytest.mark.asyncio
    async def test_pattern_filter_reduces_total(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeAddr:
            def __init__(self, name: str) -> None:
                self.name = name

            def about(self) -> dict[str, Any]:
                return {"name": self.name, "ip_netmask": "10.0.0.1/32"}

        fake_objects = [FakeAddr(n) for n in ["dmz-web", "internal-db", "dmz-mail"]]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.objects import AddressObject
        monkeypatch.setattr(AddressObject, "refreshall", staticmethod(lambda *a, **k: fake_objects))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_objects_tools(ctx)

        result = await _call(mcp, "get_address_objects", firewall="fw1", pattern="dmz")
        assert result["total"] == 2
        assert {i["name"] for i in result["items"]} == {"dmz-web", "dmz-mail"}


# --- get_security_rules (refreshall via Rulebase) ------------------------


class TestGetSecurityRules:
    @pytest.mark.asyncio
    async def test_lean_excludes_uuid_and_audit_comment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeRule:
            def __init__(self, name: str) -> None:
                self.name = name

            def about(self) -> dict[str, Any]:
                return {
                    "name": self.name,
                    "fromzone": ["trust"],
                    "tozone": ["untrust"],
                    "source": ["any"],
                    "destination": ["any"],
                    "application": ["web-browsing"],
                    "service": ["application-default"],
                    "action": "allow",
                    "disabled": False,
                    "uuid": "abc-def",
                    "audit_comment": "Approved by SecOps 2024-08-15",
                    "tag": ["compliance"],
                }

        rules = [FakeRule(f"rule-{i}") for i in range(5)]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "get_security_rules", firewall="fw1")
        assert result["count"] == 5
        for r in result["items"]:
            assert "uuid" not in r
            assert "audit_comment" not in r
            assert "tag" not in r
            assert r["action"] == "allow"
            # Derived audit booleans must be in the lean default.
            assert "has_inspection" in r
            assert "has_log_setting" in r

    @pytest.mark.asyncio
    async def test_derived_audit_flags_in_default_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default response surfaces ``has_inspection`` / ``has_log_setting``
        so the AI can answer "which rules lack inspection?" without going
        verbose. Regression for the audit-blindspot bug where neither flag
        existed in the default whitelist, and for the follow-on fix where
        the flag missed individual L7 profile attachments and reported
        100% false positives in environments that don't use profile groups.
        """

        class _Rule:
            def __init__(self, name: str, about: dict[str, Any]) -> None:
                self.name = name
                self._about = about

            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            _Rule("with-group", {
                "name": "with-group", "action": "allow", "disabled": False,
                "group": "strict-profile",  # has profile via group
                "log_setting": "to-siem",   # has log forwarding
            }),
            _Rule("with-individual-profiles", {
                "name": "with-individual-profiles", "action": "allow",
                "disabled": False,
                # No profile group, but L7 profile attachments live as
                # top-level ``.about()`` keys — the Rea-style pattern that
                # the old flag missed. ``has_inspection`` must be True.
                "virus": ["default"],
                "spyware": ["Rea Anti-Spyware Profile"],
                "url_filtering": ["Rea URL Filter"],
            }),
            _Rule("bare", {
                "name": "bare", "action": "allow", "disabled": False,
                # No profile group, no individual attachments, no logging →
                # all flags false.
                "group": None, "log_setting": None,
                "virus": None, "spyware": None, "vulnerability": None,
                "url_filtering": None, "file_blocking": None,
                "data_filtering": None, "wildfire_analysis": None,
            }),
            _Rule("empty-strings", {
                "name": "empty-strings", "action": "allow", "disabled": False,
                # Empty strings / empty lists are falsy — confirm we don't
                # treat them as set.
                "group": "", "log_setting": "",
                "virus": [], "spyware": [],
            }),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "get_security_rules", firewall="fw1")
        by_name = {r["name"]: r for r in result["items"]}

        assert by_name["with-group"]["has_inspection"] is True
        assert by_name["with-group"]["has_log_setting"] is True

        assert by_name["with-individual-profiles"]["has_inspection"] is True
        assert by_name["with-individual-profiles"]["has_log_setting"] is False

        assert by_name["bare"]["has_inspection"] is False
        assert by_name["bare"]["has_log_setting"] is False

        assert by_name["empty-strings"]["has_inspection"] is False
        assert by_name["empty-strings"]["has_log_setting"] is False

        # Raw underlying fields stay verbose-only — they're still strippable
        # by the lean shape even though the derived booleans are in the
        # default whitelist.
        assert "group" not in by_name["with-group"]
        assert "log_setting" not in by_name["with-group"]
        assert "virus" not in by_name["with-individual-profiles"]

    @pytest.mark.asyncio
    async def test_disabled_is_always_a_bool_across_the_listing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression for the schema-consistency bug: previously the lean
        response showed ``disabled: true`` on the one disabled rule and
        omitted the field entirely on every enabled rule (because
        ``.about()`` returns ``None`` and ``drop_when_none`` strips it).
        The AI then can't tell "enabled" from "field missing" by reading
        the response. Now ``disabled`` is always a real bool on every rule.
        """

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]

            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            # Enabled with explicit False — should stay False.
            _Rule({"name": "explicit-enabled", "action": "allow", "disabled": False}),
            # Enabled by omission — .about() returns None. Must coerce to False
            # rather than being dropped by drop_when_none.
            _Rule({"name": "implicit-enabled", "action": "allow", "disabled": None}),
            # Disabled with bool True — must stay True.
            _Rule({"name": "explicit-disabled", "action": "allow", "disabled": True}),
            # Disabled with PAN-OS XML "yes" string — coerce to True.
            _Rule({"name": "xml-yes", "action": "allow", "disabled": "yes"}),
            # Enabled with PAN-OS XML "no" string — coerce to False.
            _Rule({"name": "xml-no", "action": "allow", "disabled": "no"}),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))

        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(mcp, "get_security_rules", firewall="fw1")
        # Every rule must carry the field; the type must always be bool.
        for r in result["items"]:
            assert "disabled" in r, (
                f"rule {r.get('name')!r} dropped its disabled field — "
                "schema inconsistency would mask enabled-vs-missing."
            )
            assert isinstance(r["disabled"], bool), (
                f"rule {r.get('name')!r} has non-bool disabled={r['disabled']!r}"
            )

        by_name = {r["name"]: r["disabled"] for r in result["items"]}
        assert by_name == {
            "explicit-enabled": False,
            "implicit-enabled": False,
            "explicit-disabled": True,
            "xml-yes": True,
            "xml-no": False,
        }

    @pytest.mark.asyncio
    async def test_attrs_filter_matches_list_field_substring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``attrs={"source": "10.0.0.0/24"}`` returns only rules whose
        source list contains that token. Server-side filtering on a
        non-name field is exactly the audit case the toolkit's name-only
        pattern can't cover.
        """

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]
            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            _Rule({"name": "lab-net", "action": "allow",
                   "source": ["10.0.0.0/24"], "application": ["any"]}),
            _Rule({"name": "dmz-net", "action": "allow",
                   "source": ["10.1.0.0/24"], "application": ["web-browsing"]}),
            _Rule({"name": "multi", "action": "allow",
                   "source": ["192.168.1.0/24", "10.0.0.0/24"],
                   "application": ["ssh"]}),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp, "get_security_rules", firewall="fw1",
            attrs={"source": "10.0.0.0/24"},
        )
        names = sorted(r["name"] for r in result["items"])
        assert names == ["lab-net", "multi"]
        # total reflects the post-filter set, not the original count.
        assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_attrs_filter_ands_multiple_conditions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All conditions in ``attrs`` must match — equivalent to AND."""

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]
            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            _Rule({"name": "any-allow", "action": "allow",
                   "application": ["any"], "source": ["any"]}),
            _Rule({"name": "any-deny", "action": "deny",
                   "application": ["any"], "source": ["any"]}),
            _Rule({"name": "web-allow", "action": "allow",
                   "application": ["web-browsing"], "source": ["any"]}),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp, "get_security_rules", firewall="fw1",
            attrs={"application": "any", "action": "allow"},
        )
        names = sorted(r["name"] for r in result["items"])
        assert names == ["any-allow"]

    @pytest.mark.asyncio
    async def test_attrs_filter_works_against_derived_booleans(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``attrs={"has_inspection": "false"}`` must filter on the booleans
        added by enrich_security_rule_dicts — i.e. enrichment runs *before*
        filtering. This is the most common audit query ("which rules are
        missing inspection?").
        """

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]
            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            _Rule({"name": "guarded", "action": "allow", "group": "strict"}),
            _Rule({"name": "bare-1", "action": "allow"}),
            _Rule({"name": "bare-2", "action": "deny"}),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp, "get_security_rules", firewall="fw1",
            attrs={"has_inspection": "false"},
        )
        names = sorted(r["name"] for r in result["items"])
        assert names == ["bare-1", "bare-2"]

    @pytest.mark.asyncio
    async def test_attrs_rejects_old_renamed_key_with_clear_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``attrs={"has_profile": "false"}`` must hard-fail with a message
        naming the replacement key, not silently return zero rows. Silent
        empty results to an AI audit caller look like a clean bill of
        health — the same class of failure the original ``has_profile``
        logic produced. The tool now rejects the old key at entry.
        """

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]
            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            _Rule({"name": "guarded", "action": "allow", "group": "strict"}),
            _Rule({"name": "bare", "action": "allow"}),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        result = await _call(
            mcp, "get_security_rules", firewall="fw1",
            attrs={"has_profile": "false"},
        )
        assert "error" in result
        # The message must name the new key so the caller knows the fix.
        assert "has_inspection" in result["error"]
        assert "has_profile" in result["error"]
        assert result["items"] == []
        assert result["count"] == 0

    @pytest.mark.asyncio
    async def test_attrs_can_filter_on_verbose_only_field_without_verbose(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Filtering on a verbose-only field (``source``) must work with
        ``verbose=False`` — i.e. the filter sees the full enriched dict
        before lean projection strips columns out.
        """

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]
            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [
            _Rule({"name": "match-me", "action": "allow",
                   "source": ["10.5.5.5/32"], "application": ["any"]}),
            _Rule({"name": "skip-me", "action": "allow",
                   "source": ["other"], "application": ["any"]}),
        ]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        # verbose=False is the default; ``source`` IS in the default whitelist
        # (so we can't see it being stripped), but we can verify that the
        # response is still lean-shaped and that filtering worked.
        result = await _call(
            mcp, "get_security_rules", firewall="fw1",
            attrs={"source": "10.5.5.5"},
        )
        names = [r["name"] for r in result["items"]]
        assert names == ["match-me"]
        # And lean shape still applies — no verbose-only fields leak.
        assert all("uuid" not in r for r in result["items"])

    @pytest.mark.asyncio
    async def test_empty_attrs_is_passthrough(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``attrs=None`` and ``attrs={}`` both return every rule unchanged."""

        class _Rule:
            def __init__(self, about: dict[str, Any]) -> None:
                self._about = about
                self.name = about["name"]
            def about(self) -> dict[str, Any]:
                return dict(self._about)

        rules = [_Rule({"name": f"r{i}", "action": "allow"}) for i in range(3)]

        class FakeFw:
            def __init__(self, **kwargs: Any) -> None:
                self.hostname = kwargs.get("hostname", "x")
            def add(self, child: Any) -> Any:
                child.parent = self
                return child

        _patch_firewall_class(monkeypatch, FakeFw)
        from panos.policies import SecurityRule
        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(lambda *a, **k: rules))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_security_tools(ctx)

        for attrs_val in (None, {}):
            result = await _call(
                mcp, "get_security_rules", firewall="fw1", attrs=attrs_val,
            )
            assert result["count"] == 3
