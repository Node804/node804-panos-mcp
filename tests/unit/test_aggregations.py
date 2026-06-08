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
        # r1 lacks profile group AND any individual profile → counted in
        # rules_without_inspection. r2 has group → not. r3 disabled → not in
        # enabled set.
        assert result["rules_without_inspection"] == 1
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


# --- panorama_summarize_security_policy -----------------------------


class TestPanoramaSummarizeSecurityPolicy:
    """End-to-end coverage of the Panorama-aware policy summary.

    The tool must dispatch ``SecurityRule.refreshall`` by parent (DG pre, DG
    post, shared pre, shared post) so the per-rulebase breakdown is correct
    and the combined ``summary`` includes every rule in scope.
    """

    @staticmethod
    def _patch_panorama(
        monkeypatch: pytest.MonkeyPatch,
        *,
        dg_name: str,
        rules_by_parent: dict[tuple[type, str], list[Any]],
    ) -> None:
        """Patch ctx.resolve to a real Panorama and dispatch refreshall by parent.

        ``rules_by_parent`` is keyed by ``(rulebase_cls, scope)`` where scope
        is ``"dg"`` for rules under the device group and ``"shared"`` for
        rules attached directly to the Panorama.
        """
        from panos.panorama import DeviceGroup, Panorama
        from panos.policies import PostRulebase, PreRulebase, SecurityRule

        pano = Panorama("h", "u", "p")
        dg = DeviceGroup(dg_name)

        # Resolve always hands back our Panorama instance.
        monkeypatch.setattr(
            "panos_mcp.tools._common.get_client",
            lambda *a, **k: pano,
        )
        monkeypatch.setattr(
            DeviceGroup, "refreshall", staticmethod(lambda *a, **k: [dg])
        )

        def _refreshall(parent: Any, *args: Any, **kwargs: Any) -> list[Any]:
            # Parent is the PreRulebase/PostRulebase whose parent is either
            # the DeviceGroup or the Panorama. Use that chain to disambiguate.
            scope = "dg" if isinstance(parent.parent, DeviceGroup) else "shared"
            return rules_by_parent.get((type(parent), scope), [])

        monkeypatch.setattr(SecurityRule, "refreshall", staticmethod(_refreshall))
        # Stop DeviceGroup.refreshall from trying to call the Panorama in any
        # of the helper tools that share this fixture.
        _ = PreRulebase, PostRulebase  # quiet unused-import

    @pytest.mark.asyncio
    async def test_summarizes_dg_pre_and_post(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panos.policies import PostRulebase, PreRulebase

        pre_rules = [
            _FakeObj(
                name="dg-pre-1", action="allow",
                fromzone=["trust"], tozone=["untrust"],
                source=["any"], destination=["any"], application=["any"],
                disabled=False, group=None, profile_setting=None,
            ),
        ]
        post_rules = [
            _FakeObj(
                name="dg-post-1", action="deny",
                fromzone=["dmz"], tozone=["untrust"],
                source=["10.0.0.0/24"], destination=["any"], application=["tor"],
                disabled=False, group="strict",
            ),
        ]
        self._patch_panorama(
            monkeypatch,
            dg_name="Lafayette Plant",
            rules_by_parent={
                (PreRulebase, "dg"): pre_rules,
                (PostRulebase, "dg"): post_rules,
            },
        )
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(
            mcp, "panorama_summarize_security_policy",
            device_group="Lafayette Plant", firewall="fw1",
        )

        assert result["device_group"] == "Lafayette Plant"
        assert result["include_shared"] is False
        # Combined summary covers both rulebases.
        assert result["summary"]["rule_counts"]["total"] == 2
        assert result["summary"]["by_action"] == {"allow": 1, "deny": 1}
        # The any-any pre-rule must show up at the combined level AND under "pre".
        assert result["summary"]["any_any_rules"] == 1
        assert result["per_rulebase"]["pre"]["any_any_rules"] == 1
        assert result["per_rulebase"]["post"]["any_any_rules"] == 0
        # No shared keys when include_shared=False.
        assert "shared_pre" not in result["per_rulebase"]
        assert "shared_post" not in result["per_rulebase"]

    @pytest.mark.asyncio
    async def test_include_shared_folds_in_shared_rulebases(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from panos.policies import PostRulebase, PreRulebase

        shared_pre = [
            _FakeObj(
                name="shared-pre-1", action="allow",
                fromzone=["any"], tozone=["any"],
                source=["any"], destination=["any"], application=["any"],
                disabled=False, group=None, profile_setting=None,
            ),
        ]
        dg_pre = [
            _FakeObj(
                name="dg-pre-1", action="deny",
                fromzone=["trust"], tozone=["untrust"],
                source=["any"], destination=["any"], application=["tor"],
                disabled=False, group="strict",
            ),
        ]
        self._patch_panorama(
            monkeypatch,
            dg_name="OT-FWs",
            rules_by_parent={
                (PreRulebase, "dg"): dg_pre,
                (PreRulebase, "shared"): shared_pre,
                (PostRulebase, "dg"): [],
                (PostRulebase, "shared"): [],
            },
        )
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(
            mcp, "panorama_summarize_security_policy",
            device_group="OT-FWs", firewall="fw1", include_shared=True,
        )

        assert result["include_shared"] is True
        assert set(result["per_rulebase"].keys()) == {"pre", "post", "shared_pre", "shared_post"}
        # Shared pre is the only any-any rule.
        assert result["per_rulebase"]["shared_pre"]["any_any_rules"] == 1
        assert result["per_rulebase"]["pre"]["any_any_rules"] == 0
        # Combined summary covers both DG and shared rulebases.
        assert result["summary"]["rule_counts"]["total"] == 2
        assert result["summary"]["by_action"] == {"allow": 1, "deny": 1}
        # Shared-pre's "no inspection" rule must be visible somewhere — its
        # group and every individual profile field are unset, so it counts.
        assert result["per_rulebase"]["shared_pre"]["rules_without_inspection"] == 1

    @pytest.mark.asyncio
    async def test_unknown_device_group_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from panos.panorama import DeviceGroup, Panorama

        pano = Panorama("h", "u", "p")
        monkeypatch.setattr(
            "panos_mcp.tools._common.get_client", lambda *a, **k: pano,
        )
        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: []))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(
            mcp, "panorama_summarize_security_policy",
            device_group="Does-Not-Exist", firewall="fw1",
        )
        assert "error" in result
        assert "Does-Not-Exist" in result["error"]

    @pytest.mark.asyncio
    async def test_non_panorama_target_surfaces_clean_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When ``DeviceGroup.refreshall`` fails (e.g. target isn't actually a
        Panorama, or the xpath errors out), the tool returns a clean error
        dict rather than letting the exception propagate.

        Earlier versions of this tool also pre-rejected non-``Panorama``
        ``isinstance`` checks, but that gate misfired on legitimate Panorama
        clients whose class identity didn't match the locally-imported
        ``Panorama`` symbol — so we trust resolution and surface failures
        from the actual enumeration call instead.
        """
        from panos.firewall import Firewall
        from panos.panorama import DeviceGroup

        fw = Firewall("h", "u", "p")
        monkeypatch.setattr(
            "panos_mcp.tools._common.get_client", lambda *a, **k: fw,
        )

        def _boom(*_a: object, **_k: object) -> list[Any]:
            raise RuntimeError("not a panorama")

        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(_boom))
        _seed_firewall()
        ctx, mcp = _make_ctx()
        register_aggregation_tools(ctx)

        result = await _call(
            mcp, "panorama_summarize_security_policy",
            device_group="anything", firewall="fw1",
        )
        assert "error" in result
        assert "not a panorama" in result["error"]


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


class TestEnrichSecurityRuleDicts:
    """Pure-helper coverage: derived booleans match the summary's definitions."""

    def test_has_inspection_true_when_group_set(self) -> None:
        from panos_mcp.tools._common import enrich_security_rule_dicts
        out = enrich_security_rule_dicts([{"group": "strict"}])
        assert out[0]["has_inspection"] is True

    def test_has_inspection_true_when_individual_profile_set(self) -> None:
        """The Rea-style pattern: no profile group, but individual L7
        profile attachments live as top-level ``.about()`` keys. The earlier
        ``has_profile`` flag only looked at ``profile_setting`` (which
        ``.about()`` never produces) and silently marked every such rule
        as "no inspection" — the bug this rename was introduced to fix.
        """
        from panos_mcp.tools._common import enrich_security_rule_dicts
        out = enrich_security_rule_dicts([
            {"virus": ["default"], "spyware": ["Rea Anti-Spyware"]}
        ])
        assert out[0]["has_inspection"] is True

    def test_has_inspection_true_for_each_individual_profile_field(self) -> None:
        """Any single profile attachment is enough — exercise the full set
        so a future refactor that drops a field gets caught by tests.
        """
        from panos_mcp.tools._common import (
            _INDIVIDUAL_PROFILE_FIELDS,
            enrich_security_rule_dicts,
        )
        for field in _INDIVIDUAL_PROFILE_FIELDS:
            out = enrich_security_rule_dicts([{field: ["default"]}])
            assert out[0]["has_inspection"] is True, field

    def test_has_inspection_false_when_all_absent(self) -> None:
        from panos_mcp.tools._common import enrich_security_rule_dicts
        out = enrich_security_rule_dicts([{"name": "r1"}])
        assert out[0]["has_inspection"] is False
        assert out[0]["has_log_setting"] is False

    def test_has_inspection_false_when_individual_profiles_all_empty(self) -> None:
        """Empty lists / empty strings on every profile field must read as
        "no inspection" — otherwise ``drop_when_none`` + a benign ``[]``
        could fake a profile attachment.
        """
        from panos_mcp.tools._common import enrich_security_rule_dicts
        out = enrich_security_rule_dicts([{
            "virus": [], "spyware": [], "vulnerability": [],
            "url_filtering": [], "file_blocking": [],
            "data_filtering": [], "wildfire_analysis": [],
        }])
        assert out[0]["has_inspection"] is False

    def test_definition_agrees_with_summarize_rules(self) -> None:
        """``rules_without_inspection`` from ``_summarize_rules`` and the
        ``has_inspection`` flag must never disagree about what counts as
        "no inspection" — otherwise the audit tool and the rule listing
        tell different stories.
        """
        from panos_mcp.tools._common import enrich_security_rule_dicts
        rules = [
            # Profile group → has inspection.
            {"name": "a", "action": "allow", "disabled": False, "group": "g1"},
            # Individual profile attachment → has inspection (the case the
            # old ``has_profile`` heuristic missed entirely).
            {"name": "b", "action": "allow", "disabled": False,
             "virus": ["default"]},
            # Bare allow → no inspection.
            {"name": "c", "action": "allow", "disabled": False},
        ]
        enriched = enrich_security_rule_dicts([dict(r) for r in rules])
        no_inspection_via_flag = sum(1 for r in enriched if not r["has_inspection"])
        summary = _summarize_rules(rules)
        assert no_inspection_via_flag == summary["rules_without_inspection"]
        assert no_inspection_via_flag == 1


class TestFilterByAttrsPureLogic:
    """Pure-helper coverage for the AND-of-substring attribute filter."""

    def test_none_is_passthrough(self) -> None:
        from panos_mcp.tools._common import filter_by_attrs
        items: list[dict[str, Any]] = [{"name": "a"}, {"name": "b"}]
        assert filter_by_attrs(items, None) == items

    def test_empty_dict_is_passthrough(self) -> None:
        from panos_mcp.tools._common import filter_by_attrs
        items: list[dict[str, Any]] = [{"name": "a"}]
        assert filter_by_attrs(items, {}) == items

    def test_list_field_matches_any_element(self) -> None:
        from panos_mcp.tools._common import filter_by_attrs
        items = [
            {"name": "r1", "source": ["10.0.0.0/24", "any"]},
            {"name": "r2", "source": ["192.168.0.0/16"]},
        ]
        out = filter_by_attrs(items, {"source": "10.0.0.0/24"})
        assert [r["name"] for r in out] == ["r1"]

    def test_bool_field_matches_string_form(self) -> None:
        from panos_mcp.tools._common import filter_by_attrs
        items = [
            {"name": "r1", "disabled": True},
            {"name": "r2", "disabled": False},
        ]
        assert [r["name"] for r in filter_by_attrs(items, {"disabled": "true"})] == ["r1"]
        assert [r["name"] for r in filter_by_attrs(items, {"disabled": "false"})] == ["r2"]

    def test_case_insensitive_match(self) -> None:
        from panos_mcp.tools._common import filter_by_attrs
        items = [{"name": "r1", "action": "Allow"}]
        assert filter_by_attrs(items, {"action": "ALLOW"}) == items

    def test_missing_field_fails_the_condition(self) -> None:
        """An item lacking a filtered field can't satisfy it — no silent
        passthrough. Otherwise audit queries like "find rules with
        has_profile=false" would falsely include rules from a tool that
        didn't enrich its output.
        """
        from panos_mcp.tools._common import filter_by_attrs
        items = [
            {"name": "r1"},  # no source field
            {"name": "r2", "source": ["any"]},
        ]
        out = filter_by_attrs(items, {"source": "any"})
        assert [r["name"] for r in out] == ["r2"]

    def test_all_conditions_must_match(self) -> None:
        from panos_mcp.tools._common import filter_by_attrs
        items = [
            {"name": "r1", "action": "allow", "application": ["any"]},
            {"name": "r2", "action": "deny", "application": ["any"]},
            {"name": "r3", "action": "allow", "application": ["web-browsing"]},
        ]
        out = filter_by_attrs(items, {"action": "allow", "application": "any"})
        assert [r["name"] for r in out] == ["r1"]


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
