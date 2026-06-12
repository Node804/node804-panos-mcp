"""End-to-end coverage for the bulk Panorama walkers.

These two tools replace N × M per-DG calls when an AI needs to audit across
every device group:

  - ``panorama_count_rules_per_device_group`` — tiny snapshot of rule counts,
    used to skip empty DGs before drilling in.
  - ``panorama_walk_all_rules`` — one call returning rules tagged with their
    origin (device_group / rulebase / rule_type) across the whole policy.

The fixture mirrors a multi-DG Panorama and dispatches ``refreshall`` by
parent so each rulebase × type combination returns the right canned list.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import Mode, ModeGate, TlsConfig, open_sink
from panos.panorama import DeviceGroup, Panorama
from panos.policies import (
    DecryptionRule,
    NatRule,
    PolicyBasedForwarding,
    PreRulebase,
    SecurityRule,
)

import panos_mcp.config.firewalls as fw_module
from panos_mcp.client import reset_client_cache
from panos_mcp.config.firewalls import FirewallEntry
from panos_mcp.tools._common import ToolContext
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


def _seed() -> None:
    fw_module._entries.append(FirewallEntry(name="pano", host="10.0.0.1", api_key="k"))


def _make_ctx() -> tuple[ToolContext, FastMCP]:
    mcp = FastMCP("test")
    gate = ModeGate(mode=Mode.READ, env_var="PANOS_MODE", audit_sink=open_sink({}))
    return ToolContext(mcp=mcp, gate=gate, tls=TlsConfig()), mcp


async def _call(mcp: FastMCP, tool: str, **kwargs: Any) -> Any:
    entry = (mcp._tool_manager._tools or {}).get(tool)  # type: ignore[attr-defined]
    if entry is None:
        raise AssertionError(f"tool '{tool}' not registered")
    return await entry.fn(**kwargs)


class _FakeObj:
    """pan-os-python object stand-in with an .about() dict."""

    def __init__(self, **data: Any) -> None:
        self._data = data
        self.name = data.get("name")

    def about(self) -> dict[str, Any]:
        return dict(self._data)


def _wire_panorama(
    monkeypatch: pytest.MonkeyPatch,
    *,
    device_groups: list[str],
    rules_by_parent: dict[tuple[type, str, str], list[Any]],
) -> Panorama:
    """Stand up a fake Panorama and route refreshall by (cls, dg_name|<shared>, rb).

    ``rules_by_parent`` is keyed ``(rule_class, dg_name_or_'<shared>', 'pre'|'post')``.
    Missing keys → empty list.
    """
    pano = Panorama("h", "u", "p")
    dgs = [DeviceGroup(name) for name in device_groups]

    monkeypatch.setattr(
        "panos_mcp.tools._common.get_client",
        lambda *a, **k: pano,
    )
    monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: dgs))

    def _dispatch(cls: type) -> staticmethod:
        def _refresh(parent: Any, *_a: Any, **_kw: Any) -> list[Any]:
            # parent is a PreRulebase/PostRulebase; its parent is either
            # the Panorama (shared) or a DeviceGroup.
            grandparent = parent.parent
            dg_name = grandparent.name if isinstance(grandparent, DeviceGroup) else "<shared>"
            rb_label = "pre" if isinstance(parent, PreRulebase) else "post"
            return rules_by_parent.get((cls, dg_name, rb_label), [])

        return staticmethod(_refresh)

    for cls in (SecurityRule, NatRule, PolicyBasedForwarding, DecryptionRule):
        monkeypatch.setattr(cls, "refreshall", _dispatch(cls))
    return pano


# ── panorama_count_rules_per_device_group ────────────────────────────────


class TestCountRulesPerDeviceGroup:
    @pytest.mark.asyncio
    async def test_returns_counts_per_dg_per_rulebase_per_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["Lafayette Plant", "OT-FWs", "Empty-DG"],
            rules_by_parent={
                (SecurityRule, "Lafayette Plant", "pre"): [
                    _FakeObj(name=f"sec-{i}") for i in range(12)
                ],
                (SecurityRule, "Lafayette Plant", "post"): [_FakeObj(name="default")],
                (NatRule, "Lafayette Plant", "pre"): [_FakeObj(name="nat-1")],
                (SecurityRule, "OT-FWs", "pre"): [_FakeObj(name=f"ot-{i}") for i in range(3)],
                # Empty-DG intentionally has no entries — the count tool is
                # exactly what lets the AI skip it.
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(mcp, "panorama_count_rules_per_device_group", firewall="pano")

        assert result["per_device_group"]["Lafayette Plant"]["pre"]["security"] == 12
        assert result["per_device_group"]["Lafayette Plant"]["post"]["security"] == 1
        assert result["per_device_group"]["Lafayette Plant"]["pre"]["nat"] == 1
        assert result["per_device_group"]["OT-FWs"]["pre"]["security"] == 3
        # Empty DG still appears with all zeros — the AI gets to see "this
        # DG exists but has nothing", not just an absence.
        empty = result["per_device_group"]["Empty-DG"]
        assert empty["pre"] == {"security": 0, "nat": 0, "pbf": 0, "decryption": 0}
        assert empty["post"] == {"security": 0, "nat": 0, "pbf": 0, "decryption": 0}
        # Totals sum across DGs and rulebases.
        assert result["totals"]["security"] == 12 + 1 + 3
        assert result["totals"]["nat"] == 1
        # No shared block by default.
        assert "shared" not in result

    @pytest.mark.asyncio
    async def test_include_shared_adds_shared_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["DG-1"],
            rules_by_parent={
                (SecurityRule, "<shared>", "pre"): [_FakeObj(name="global-allow")],
                (SecurityRule, "DG-1", "pre"): [_FakeObj(name="dg-allow")],
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_count_rules_per_device_group",
            firewall="pano",
            include_shared=True,
        )
        assert result["shared"]["pre"]["security"] == 1
        assert result["totals"]["security"] == 2

    @pytest.mark.asyncio
    async def test_rule_types_scoping_reduces_round_trips(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When ``rule_types=['security']`` we shouldn't call refreshall on
        the other three classes — that's the API-cost win the param exists
        for. We count calls on each class.
        """
        call_counts: dict[str, int] = {"sec": 0, "nat": 0, "pbf": 0, "dec": 0}

        pano = Panorama("h", "u", "p")
        dg = DeviceGroup("DG-1")
        monkeypatch.setattr(
            "panos_mcp.tools._common.get_client",
            lambda *a, **k: pano,
        )
        monkeypatch.setattr(DeviceGroup, "refreshall", staticmethod(lambda *a, **k: [dg]))

        def _count(label: str) -> staticmethod:
            def _refresh(*_a: Any, **_kw: Any) -> list[Any]:
                call_counts[label] += 1
                return []

            return staticmethod(_refresh)

        monkeypatch.setattr(SecurityRule, "refreshall", _count("sec"))
        monkeypatch.setattr(NatRule, "refreshall", _count("nat"))
        monkeypatch.setattr(PolicyBasedForwarding, "refreshall", _count("pbf"))
        monkeypatch.setattr(DecryptionRule, "refreshall", _count("dec"))

        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        await _call(
            mcp,
            "panorama_count_rules_per_device_group",
            firewall="pano",
            rule_types=["security"],
        )
        # One DG × two rulebases × security only = 2 calls; other classes untouched.
        assert call_counts == {"sec": 2, "nat": 0, "pbf": 0, "dec": 0}

    @pytest.mark.asyncio
    async def test_unknown_rule_type_returns_clean_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(monkeypatch, device_groups=["DG-1"], rules_by_parent={})
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        # MCP validates Literal at the schema layer, so call the underlying fn
        # directly with an invalid type to exercise the in-tool guard.
        result = await _call(
            mcp,
            "panorama_count_rules_per_device_group",
            firewall="pano",
            rule_types=["bogus"],
        )
        assert "error" in result
        assert "bogus" in result["error"]


# ── panorama_walk_all_rules ──────────────────────────────────────────────


class TestWalkAllRules:
    @pytest.mark.asyncio
    async def test_returns_items_tagged_with_origin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["Lafayette Plant", "OT-FWs"],
            rules_by_parent={
                (SecurityRule, "Lafayette Plant", "pre"): [
                    _FakeObj(
                        name="laf-pre-1",
                        action="allow",
                        source=["10.0.0.0/24"],
                        application=["any"],
                        disabled=False,
                    ),
                ],
                (SecurityRule, "Lafayette Plant", "post"): [
                    _FakeObj(
                        name="laf-post-1",
                        action="deny",
                        source=["any"],
                        application=["any"],
                        disabled=False,
                    ),
                ],
                (SecurityRule, "OT-FWs", "pre"): [
                    _FakeObj(
                        name="ot-pre-1",
                        action="allow",
                        source=["any"],
                        application=["modbus"],
                        disabled=False,
                    ),
                ],
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            rule_types=["security"],
        )

        assert result["scope"]["device_groups"] == ["Lafayette Plant", "OT-FWs"]
        assert result["scope"]["rule_types"] == ["security"]
        assert result["scope"]["include_shared"] is False
        assert result["total"] == 3

        # Every item must carry the three origin tags so the caller can
        # group/drill back — that's the whole point of the bulk walker.
        for item in result["items"]:
            assert "device_group" in item
            assert "rulebase" in item
            assert "rule_type" in item
            assert item["rule_type"] == "security"

        by_origin = {(i["device_group"], i["rulebase"], i["name"]) for i in result["items"]}
        assert by_origin == {
            ("Lafayette Plant", "pre", "laf-pre-1"),
            ("Lafayette Plant", "post", "laf-post-1"),
            ("OT-FWs", "pre", "ot-pre-1"),
        }

    @pytest.mark.asyncio
    async def test_attrs_filter_works_across_dgs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An audit query like ``attrs={"source": "10.0.0.0/24"}`` should
        only return rules matching that condition regardless of which DG
        they live in — the savings vs N per-DG calls scale with DG count.
        """
        _wire_panorama(
            monkeypatch,
            device_groups=["DG-A", "DG-B", "DG-C"],
            rules_by_parent={
                (SecurityRule, "DG-A", "pre"): [
                    _FakeObj(
                        name="hit-a", action="allow", source=["10.0.0.0/24"], application=["any"]
                    ),
                    _FakeObj(
                        name="miss-a",
                        action="allow",
                        source=["192.168.0.0/16"],
                        application=["any"],
                    ),
                ],
                (SecurityRule, "DG-B", "pre"): [
                    _FakeObj(
                        name="hit-b",
                        action="allow",
                        source=["10.0.0.0/24", "any"],
                        application=["any"],
                    ),
                ],
                (SecurityRule, "DG-C", "pre"): [
                    _FakeObj(
                        name="miss-c", action="allow", source=["172.16.0.0/12"], application=["any"]
                    ),
                ],
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            rule_types=["security"],
            attrs={"source": "10.0.0.0/24"},
        )
        names = sorted(i["name"] for i in result["items"])
        assert names == ["hit-a", "hit-b"]
        # Origin tags still present after filtering + projection.
        for i in result["items"]:
            assert i["device_group"] in ("DG-A", "DG-B")
            assert i["rulebase"] == "pre"

    @pytest.mark.asyncio
    async def test_device_groups_scoping_skips_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["DG-A", "DG-B"],
            rules_by_parent={
                (SecurityRule, "DG-A", "pre"): [_FakeObj(name="a-1", action="allow")],
                (SecurityRule, "DG-B", "pre"): [_FakeObj(name="b-1", action="allow")],
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            rule_types=["security"],
            device_groups=["DG-A"],
        )
        assert {i["name"] for i in result["items"]} == {"a-1"}
        assert result["scope"]["device_groups"] == ["DG-A"]

    @pytest.mark.asyncio
    async def test_unknown_device_group_returns_clean_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(monkeypatch, device_groups=["DG-A"], rules_by_parent={})
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            device_groups=["Does-Not-Exist"],
        )
        assert "error" in result
        assert "Does-Not-Exist" in result["error"]

    @pytest.mark.asyncio
    async def test_walks_multiple_rule_types_with_per_type_shapes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each rule type uses its own lean shape — a NAT rule's projection
        should differ from a security rule's. The walker still tags both
        with origin metadata so the AI can pick them apart by type.
        """
        _wire_panorama(
            monkeypatch,
            device_groups=["DG-1"],
            rules_by_parent={
                (SecurityRule, "DG-1", "pre"): [
                    _FakeObj(
                        name="sec-1",
                        action="allow",
                        source=["any"],
                        application=["any"],
                        disabled=False,
                    ),
                ],
                (NatRule, "DG-1", "pre"): [
                    _FakeObj(
                        name="nat-1", source=["10.0.0.0/24"], destination=["any"], service="any"
                    ),
                ],
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            rule_types=["security", "nat"],
        )
        by_type = {i["rule_type"]: i for i in result["items"]}
        assert set(by_type) == {"security", "nat"}
        # Security rule carries its enrichment (has_inspection, has_log_setting).
        assert "has_inspection" in by_type["security"]
        # NAT rule does NOT get those — different shape.
        assert "has_inspection" not in by_type["nat"]

    @pytest.mark.asyncio
    async def test_include_shared_walks_panorama_level(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_panorama(
            monkeypatch,
            device_groups=["DG-1"],
            rules_by_parent={
                (SecurityRule, "<shared>", "pre"): [
                    _FakeObj(name="global", action="allow"),
                ],
                (SecurityRule, "DG-1", "pre"): [
                    _FakeObj(name="local", action="allow"),
                ],
            },
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            rule_types=["security"],
            include_shared=True,
        )
        by_origin = {(i["device_group"], i["name"]) for i in result["items"]}
        assert by_origin == {("DG-1", "local"), ("<shared>", "global")}
        assert result["scope"]["include_shared"] is True

    @pytest.mark.asyncio
    async def test_pagination_caps_response_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from node804_mcp_toolkit import Pagination

        rules = [_FakeObj(name=f"r-{i}", action="allow") for i in range(250)]
        _wire_panorama(
            monkeypatch,
            device_groups=["DG-1"],
            rules_by_parent={(SecurityRule, "DG-1", "pre"): rules},
        )
        _seed()
        ctx, mcp = _make_ctx()
        register_panorama_tools(ctx)

        result = await _call(
            mcp,
            "panorama_walk_all_rules",
            firewall="pano",
            rule_types=["security"],
            pagination=Pagination(limit=50, offset=0),
        )
        assert result["count"] == 50
        assert result["total"] == 250
