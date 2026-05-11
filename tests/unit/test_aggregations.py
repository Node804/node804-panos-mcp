"""Tests for Phase 7 aggregation tools.

Coverage focus:
  - count_rules_by_action: action breakdown correct, disabled excluded
  - find_rule_by_name: substring match, type tagging, rule_types scoping
  - find_address_object: IP vs name dispatch, IP membership (netmask + range)
  - summarize_security_policy: any-any detection, zone collection, action counts
  - count_objects_by_type: type breakdown across addresses/services/groups
  - Token efficiency: aggregations produce dramatically smaller responses than
    the equivalent dump-and-filter pattern

All aggregation tools require Mode.READ — same tier as their underlying reads.
"""

from __future__ import annotations

import json
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
from panos_mcp.tools.aggregations import (
    _filter_address_objects_by_query,
    _summarize_rules,
    _try_parse_ip_range,
    _try_parse_network,
    register_aggregation_tools,
)


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


def _seed_firewall() -> None:
    fw_module._entries.append(FirewallEntry(name="fw1", host="10.0.0.1", api_key="k"))


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


async def _call(mcp: FastMCP, tool: str, **kwargs: Any) -> Any:
    entry = (mcp._tool_manager._tools or {}).get(tool)  # type: ignore[attr-defined]
    if entry is None:
        raise AssertionError(f"tool '{tool}' not registered")
    return await entry.fn(**kwargs)


def _patch_panos(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    """Patch pan-os-python class refreshall methods to return faked objects.

    overrides keys: 'security', 'nat', 'pbf', 'decryption', 'address',
    'address_group', 'service', 'service_group', 'tag', 'app_filter'.
    Each value is a list of objects exposing .about() -> dict.
    """

    class FakeFw:
        def __init__(self, **kwargs: Any) -> None:
            self.hostname = kwargs.get("hostname", "10.0.0.1")
        def add(self, child: Any) -> Any:
            child.parent = self
            return child

    monkeypatch.setattr(client_module, "Firewall", FakeFw)

    from panos.objects import (
        AddressGroup,
        AddressObject,
        ApplicationFilter,
        ServiceGroup,
        ServiceObject,
        Tag,
    )
    from panos.policies import (
        DecryptionRule,
        NatRule,
        PolicyBasedForwarding,
        SecurityRule,
    )

    pairs = [
        ("security", SecurityRule),
        ("nat", NatRule),
        ("pbf", PolicyBasedForwarding),
        ("decryption", DecryptionRule),
        ("address", AddressObject),
        ("address_group", AddressGroup),
        ("service", ServiceObject),
        ("service_group", ServiceGroup),
        ("tag", Tag),
        ("app_filter", ApplicationFilter),
    ]
    for key, cls in pairs:
        items = overrides.get(key, [])
        monkeypatch.setattr(cls, "refreshall", staticmethod(lambda *a, _items=items, **k: _items))


class _FakeObj:
    """Stand-in for a pan-os-python object with an .about() dict."""

    def __init__(self, **data: Any) -> None:
        self._data = data
        self.name = data.get("name")

    def about(self) -> dict[str, Any]:
        return dict(self._data)


# --- Helpers: IP parsing -----------------------------------------------


class TestNetworkHelpers:
    def test_try_parse_network_handles_ip_and_cidr(self) -> None:
        assert _try_parse_network("10.0.0.5") is not None
        assert _try_parse_network("10.0.0.0/24") is not None
        assert _try_parse_network("not-an-ip") is None
        assert _try_parse_network("evil-rule-name") is None

    def test_try_parse_ip_range_handles_dash_format(self) -> None:
        result = _try_parse_ip_range("10.0.0.1-10.0.0.10")
        assert result is not None
        low, high = result
        assert high - low == 9

    def test_try_parse_ip_range_returns_none_for_garbage(self) -> None:
        assert _try_parse_ip_range("10.0.0.1") is None
        assert _try_parse_ip_range("nope") is None


# --- count_rules_by_action --------------------------------------------


class TestCountRulesByAction:
    @pytest.mark.asyncio
    async def test_groups_by_action_and_excludes_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rules = [
            _FakeObj(name="r1", action="allow", disabled=False),
            _FakeObj(name="r2", action="allow", disabled=False),
            _FakeObj(name="r3", action="deny", disabled=False),
            _FakeObj(name="r4", action="drop", disabled=True),
            _FakeObj(name="r5", action="allow", disabled="yes"),  # PAN-OS-style string
        ]
        _patch_panos(monkeypatch, security=rules)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "count_rules_by_action", firewall="fw1")
        assert result["total"] == 5
        assert result["enabled"] == 3
        assert result["disabled"] == 2
        # by_action counts only enabled rules
        assert result["by_action"] == {"allow": 2, "deny": 1}


# --- find_rule_by_name ------------------------------------------------


class TestFindRuleByName:
    @pytest.mark.asyncio
    async def test_substring_match_across_types(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_panos(
            monkeypatch,
            security=[_FakeObj(name="block-tor", action="deny")],
            nat=[_FakeObj(name="block-tor-snat", source=["any"])],
            pbf=[_FakeObj(name="unrelated", action="forward")],
            decryption=[_FakeObj(name="dec-block-tor", action="decrypt")],
        )
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "find_rule_by_name", pattern="block-tor", firewall="fw1")
        assert result["count"] == 3
        types = {m["type"] for m in result["matches"]}
        assert types == {"security", "nat", "decryption"}

    @pytest.mark.asyncio
    async def test_rule_types_scopes_the_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_panos(
            monkeypatch,
            security=[_FakeObj(name="match-1")],
            nat=[_FakeObj(name="match-2")],
        )
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(
            mcp, "find_rule_by_name",
            pattern="match",
            rule_types=["security"],
            firewall="fw1",
        )
        assert result["count"] == 1
        assert result["matches"][0]["type"] == "security"

    @pytest.mark.asyncio
    async def test_case_insensitive_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_panos(monkeypatch, security=[_FakeObj(name="Block-Tor")])
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "find_rule_by_name", pattern="BLOCK", firewall="fw1")
        assert result["count"] == 1


# --- find_address_object ----------------------------------------------


class TestFindAddressObject:
    @pytest.mark.asyncio
    async def test_ip_membership_dispatches_to_ip_strategy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        addresses = [
            _FakeObj(name="web-srv-1", ip_netmask="10.0.0.5/32"),
            _FakeObj(name="web-srv-2", ip_netmask="10.0.0.0/24"),
            _FakeObj(name="dmz-host", ip_netmask="192.168.1.10/32"),
            _FakeObj(name="range-block", ip_range="10.0.0.1-10.0.0.50"),
        ]
        _patch_panos(monkeypatch, address=addresses)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "find_address_object", query="10.0.0.5", firewall="fw1")
        assert result["strategy"] == "ip"
        names = {m["name"] for m in result["matches"]}
        # /32 exact, /24 containing, and range covering 10.0.0.5 — all match.
        # dmz-host doesn't match.
        assert names == {"web-srv-1", "web-srv-2", "range-block"}
        for m in result["matches"]:
            assert m["match_type"] == "ip_membership"

    @pytest.mark.asyncio
    async def test_name_substring_when_query_isnt_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        addresses = [
            _FakeObj(name="web-srv-1", ip_netmask="10.0.0.5/32"),
            _FakeObj(name="db-server", ip_netmask="10.0.0.10/32"),
        ]
        _patch_panos(monkeypatch, address=addresses)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "find_address_object", query="web", firewall="fw1")
        assert result["strategy"] == "name"
        assert result["count"] == 1
        assert result["matches"][0]["name"] == "web-srv-1"
        assert result["matches"][0]["match_type"] == "name_substring"


# --- summarize_security_policy --------------------------------------


class TestSummarizeSecurityPolicy:
    @pytest.mark.asyncio
    async def test_reports_full_summary_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rules = [
            _FakeObj(
                name="r1",
                action="allow",
                fromzone=["trust"],
                tozone=["untrust"],
                source=["any"],
                destination=["any"],
                application=["any"],
                disabled=False,
                group=None,
                profile_setting=None,
            ),
            _FakeObj(
                name="r2",
                action="deny",
                fromzone=["dmz"],
                tozone=["untrust"],
                source=["any"],
                destination=["any"],
                application=["tor"],
                disabled=False,
                group="strict",
            ),
            _FakeObj(
                name="r3",
                action="allow",
                fromzone=["trust"],
                tozone=["dmz"],
                source=["10.0.0.0/24"],
                destination=["any"],
                application=["any"],
                disabled=True,
                group=None,
            ),
        ]
        _patch_panos(monkeypatch, security=rules)
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "summarize_security_policy", firewall="fw1")
        assert result["rule_counts"]["total"] == 3
        assert result["rule_counts"]["enabled"] == 2
        assert result["rule_counts"]["disabled"] == 1
        # r1 is any-any-any → counted; r2 has app=tor → not; r3 disabled → not counted.
        assert result["any_any_rules"] == 1
        # r1 lacks profile group AND profile_setting → counted in no_profile.
        # r2 has group → not. r3 disabled → not in enabled set.
        assert result["rules_without_profiles"] == 1
        assert "trust" in result["zones_referenced"]
        assert "untrust" in result["zones_referenced"]
        assert "dmz" in result["zones_referenced"]
        assert result["by_action"] == {"allow": 1, "deny": 1}


# --- count_objects_by_type ------------------------------------------


class TestCountObjectsByType:
    @pytest.mark.asyncio
    async def test_breaks_down_address_types(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_panos(
            monkeypatch,
            address=[
                _FakeObj(name="a1", ip_netmask="10.0.0.1/32"),
                _FakeObj(name="a2", ip_netmask="10.0.0.0/24"),
                _FakeObj(name="a3", fqdn="example.com"),
                _FakeObj(name="a4", ip_range="10.0.0.1-10.0.0.10"),
            ],
            address_group=[
                _FakeObj(name="g1", static_value=["a1", "a2"]),
                _FakeObj(name="g2", dynamic_value="filter expr"),
            ],
            service=[
                _FakeObj(name="s1", protocol="tcp", destination_port="443"),
                _FakeObj(name="s2", protocol="udp", destination_port="53"),
            ],
            service_group=[_FakeObj(name="sg1")],
            tag=[_FakeObj(name="t1"), _FakeObj(name="t2"), _FakeObj(name="t3")],
            app_filter=[],
        )
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(mcp, "count_objects_by_type", firewall="fw1")
        assert result["address_objects"]["total"] == 4
        assert result["address_objects"]["by_type"]["ip-netmask"] == 2
        assert result["address_objects"]["by_type"]["fqdn"] == 1
        assert result["address_objects"]["by_type"]["ip-range"] == 1
        assert result["address_groups"]["total"] == 2
        assert result["address_groups"]["static"] == 1
        assert result["address_groups"]["dynamic"] == 1
        assert result["service_objects"]["by_protocol"] == {"tcp": 1, "udp": 1}
        assert result["service_groups"] == 1
        assert result["tags"] == 3
        assert result["application_filters"] == 0


# --- Pure-helper tests -----------------------------------------------


class TestSummarizeRulesPureLogic:
    def test_empty_rules(self) -> None:
        result = _summarize_rules([])
        assert result["rule_counts"]["total"] == 0
        assert result["by_action"] == {}
        assert result["any_any_rules"] == 0

    def test_disabled_string_yes_excludes_rule(self) -> None:
        rules = [
            {"name": "r1", "action": "allow", "disabled": "yes"},
            {"name": "r2", "action": "deny", "disabled": "no"},
        ]
        result = _summarize_rules(rules)
        assert result["by_action"] == {"deny": 1}


class TestAddressFilterPureLogic:
    def test_returns_ip_strategy_for_ip_query(self) -> None:
        objects: list[dict[str, Any]] = [{"name": "x", "ip_netmask": "10.0.0.1/32"}]
        _, strategy = _filter_address_objects_by_query(objects, "10.0.0.1")
        assert strategy == "ip"

    def test_returns_name_strategy_for_text_query(self) -> None:
        objects: list[dict[str, Any]] = [{"name": "web-srv", "ip_netmask": "10.0.0.1/32"}]
        _, strategy = _filter_address_objects_by_query(objects, "web")
        assert strategy == "name"


# --- Token efficiency claim -----------------------------------------


class TestTokenEfficiency:
    """Aggregation responses must be dramatically smaller than full inventories.

    These tests don't run pan-os-python at all — they synthesize the lean
    aggregation response and the equivalent verbose dump, then compare sizes.
    Guards the "10-20x cheaper" claim in the README.
    """

    def test_summarize_vs_full_rule_dump(self) -> None:
        # Build a realistic 100-rule fake policy.
        rules: list[dict[str, Any]] = [
            {
                "name": f"rule-{i:03d}",
                "fromzone": ["trust"],
                "tozone": ["untrust"],
                "source": ["any"],
                "destination": ["any"],
                "application": ["web-browsing", "ssl", "social-networking"],
                "service": ["application-default"],
                "action": "allow" if i % 3 != 0 else "deny",
                "disabled": False,
                "log_end": True,
                "log_start": False,
                "group": "strict-profile",
                "tag": ["compliance", f"v{i // 10}"],
                "description": f"Long description for rule {i} explaining why it exists.",
                "uuid": f"01234567-89ab-cdef-{i:04d}-0123456789ab",
            }
            for i in range(100)
        ]
        verbose_dump = json.dumps({"total": 100, "items": rules})
        summary = json.dumps(_summarize_rules(rules))

        ratio = len(verbose_dump) / max(len(summary), 1)
        assert ratio >= 10, (
            f"summarize_security_policy should be >=10x smaller than the full dump; "
            f"got {ratio:.1f}x (dump={len(verbose_dump)}, summary={len(summary)})"
        )
