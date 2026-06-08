"""Regression tests for ``panorama_get_device_group_hierarchy``.

The previous implementation read ``parent_dg`` off the pan-os-python
``DeviceGroup`` model, which is sourced from the writable
``/config/devices/.../device-group`` tree where that field is not stored —
so every entry came back with ``parent_dg = None``. The fix calls
``show dg-hierarchy`` and walks the nested XML preserving the parent at
every level. These tests pin both that contract and recursion to depth ≥ 2.

The fixture mirrors Rea's real Panorama (Internet-FWs / OT-FWs under Shared,
site DGs under Internet-FWs, "Warehouse - BAB" a grandchild) so we'd catch
the original flattening bug.
"""

from __future__ import annotations

from typing import Any

from panos_mcp.tools.panorama import _walk_dg_hierarchy


def _rea_response() -> dict[str, Any]:
    """A dict shaped like ``op_to_dict(client, 'show dg-hierarchy')`` against
    a depth-3 Panorama. Mirrors what element_to_dict produces from::

        <dg-hierarchy>
          <dg name="Shared">
            <dg name="Internet-FWs">
              <dg name="Lafayette Plant"/>
              <dg name="Warehouse - BAB"/>
            </dg>
            <dg name="OT-FWs"/>
          </dg>
        </dg-hierarchy>
    """
    return {
        "dg-hierarchy": {
            "dg": {
                "@_name": "Shared",
                "dg": [
                    {
                        "@_name": "Internet-FWs",
                        "dg": [
                            {"@_name": "Lafayette Plant"},
                            {"@_name": "Warehouse - BAB"},
                        ],
                    },
                    {"@_name": "OT-FWs"},
                ],
            }
        }
    }


def test_top_level_dg_has_null_parent() -> None:
    rows = _walk_dg_hierarchy(_rea_response())
    by_name = {r["name"]: r["parent_dg"] for r in rows}
    assert by_name["Shared"] is None


def test_direct_children_record_their_parent() -> None:
    rows = _walk_dg_hierarchy(_rea_response())
    by_name = {r["name"]: r["parent_dg"] for r in rows}
    assert by_name["Internet-FWs"] == "Shared"
    assert by_name["OT-FWs"] == "Shared"


def test_grandchildren_record_intermediate_parent() -> None:
    """The original bug: depth-3 entries had parent_dg=None instead of their
    actual parent DG.
    """
    rows = _walk_dg_hierarchy(_rea_response())
    by_name = {r["name"]: r["parent_dg"] for r in rows}
    assert by_name["Lafayette Plant"] == "Internet-FWs"
    assert by_name["Warehouse - BAB"] == "Internet-FWs"


def test_at_least_one_non_null_parent_against_multi_dg_panorama() -> None:
    """Suggested regression assertion from the bug report — applies to any
    Panorama with more than one DG.
    """
    rows = _walk_dg_hierarchy(_rea_response())
    assert len(rows) > 1
    assert any(r["parent_dg"] is not None for r in rows)


def test_reconstructed_tree_depth_at_least_two() -> None:
    """Walk parent edges to compute each node's depth; the fixture must
    contain something at depth ≥ 2 (grandchild). This is the exact check that
    would have caught the flat-list bug.
    """
    rows = _walk_dg_hierarchy(_rea_response())
    parents = {r["name"]: r["parent_dg"] for r in rows}

    def depth(name: str) -> int:
        d = 0
        cur = parents.get(name)
        seen = {name}
        while cur is not None and cur not in seen:
            seen.add(cur)
            d += 1
            cur = parents.get(cur)
        return d

    assert max(depth(n) for n in parents) >= 2


def test_single_child_node_not_in_list_form() -> None:
    """element_to_dict wraps repeated children in a list but leaves a sole
    child as a bare dict. The walker must handle both shapes.
    """
    payload = {
        "dg-hierarchy": {
            "dg": {
                "@_name": "Root",
                "dg": {"@_name": "Only-Child", "dg": {"@_name": "Grandchild"}},
            }
        }
    }
    rows = _walk_dg_hierarchy(payload)
    parents = {r["name"]: r["parent_dg"] for r in rows}
    assert parents == {
        "Root": None,
        "Only-Child": "Root",
        "Grandchild": "Only-Child",
    }


def test_empty_or_missing_payload_returns_empty_list() -> None:
    assert _walk_dg_hierarchy({}) == []
    assert _walk_dg_hierarchy({"dg-hierarchy": None}) == []
    assert _walk_dg_hierarchy({"dg-hierarchy": {}}) == []


def test_entries_without_name_are_skipped() -> None:
    payload = {
        "dg-hierarchy": {
            "dg": [
                {"@_name": "Real"},
                {"description": "no name attr"},  # should be ignored
            ]
        }
    }
    rows = _walk_dg_hierarchy(payload)
    assert [r["name"] for r in rows] == ["Real"]
