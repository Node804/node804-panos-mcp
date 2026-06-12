"""Tests for the response-shaping pipeline (shapers.py).

The shaping pipeline is the centerpiece of token efficiency, so it gets
thorough coverage. We exercise:
  - default whitelist
  - verbose=True bypass
  - explicit fields override
  - None-value dropping
  - extra_strip_keys (for PAN-OS internals)
  - pattern filtering
  - pagination
  - shape_single for one-record responses
"""

from __future__ import annotations

from node804_mcp_toolkit import Pagination

from panos_mcp.responses.shapers import LeanShape, apply_shape, shape_single


def test_default_whitelist_drops_unlisted_fields() -> None:
    items = [{"name": "a", "x": 1, "uuid": "abc"}, {"name": "b", "x": 2, "uuid": "def"}]
    shape = LeanShape(default_fields=("name", "x"))
    result = apply_shape(items, shape=shape)
    assert all("uuid" not in i for i in result["items"])
    assert all("name" in i and "x" in i for i in result["items"])


def test_verbose_keeps_everything() -> None:
    items = [{"name": "a", "x": 1, "uuid": "abc"}]
    shape = LeanShape(default_fields=("name",))
    result = apply_shape(items, shape=shape, verbose=True)
    assert result["items"][0] == {"name": "a", "x": 1, "uuid": "abc"}


def test_explicit_fields_overrides_default_whitelist() -> None:
    items = [{"name": "a", "x": 1, "uuid": "abc"}]
    shape = LeanShape(default_fields=("name", "x"))
    result = apply_shape(items, shape=shape, fields=["uuid"])
    assert result["items"][0] == {"uuid": "abc"}


def test_none_values_dropped_by_default() -> None:
    items = [{"name": "a", "description": None, "tag": None}]
    shape = LeanShape(default_fields=("name", "description", "tag"))
    result = apply_shape(items, shape=shape)
    assert result["items"][0] == {"name": "a"}


def test_none_values_kept_when_disabled() -> None:
    items = [{"name": "a", "description": None}]
    shape = LeanShape(default_fields=("name", "description"), drop_when_none=False)
    result = apply_shape(items, shape=shape)
    assert result["items"][0] == {"name": "a", "description": None}


def test_extra_strip_keys_recursive() -> None:
    items = [
        {
            "name": "rule1",
            "@_uuid": "xxx",
            "@_dirtyId": "1",
            "nested": {"@_uuid": "yyy", "child": "ok"},
        }
    ]
    shape = LeanShape(extra_strip_keys=("@_uuid", "@_dirtyId"))
    result = apply_shape(items, shape=shape, verbose=True)
    item = result["items"][0]
    assert "@_uuid" not in item
    assert "@_dirtyId" not in item
    assert item["nested"] == {"child": "ok"}


def test_pattern_filter_substring_case_insensitive() -> None:
    items = [
        {"name": "block-tor"},
        {"name": "allow-web"},
        {"name": "Block-social"},
    ]
    shape = LeanShape(default_fields=("name",))
    result = apply_shape(items, shape=shape, pattern="BLOCK")
    assert result["total"] == 2  # pre-pagination total reflects matched items
    assert {i["name"] for i in result["items"]} == {"block-tor", "Block-social"}


def test_pagination_respects_limit_offset() -> None:
    items = [{"name": f"r{i}"} for i in range(20)]
    shape = LeanShape(default_fields=("name",))
    result = apply_shape(items, shape=shape, pagination=Pagination(limit=5, offset=10))
    assert result["count"] == 5
    assert result["total"] == 20  # total reflects pre-pagination
    assert [i["name"] for i in result["items"]] == [f"r{i}" for i in range(10, 15)]


def test_pattern_then_pagination() -> None:
    items = [{"name": f"block-{i}" if i % 2 == 0 else f"allow-{i}"} for i in range(10)]
    shape = LeanShape(default_fields=("name",))
    result = apply_shape(
        items, shape=shape, pattern="block", pagination=Pagination(limit=2, offset=0)
    )
    # 5 items match "block", first 2 returned.
    assert result["total"] == 5
    assert result["count"] == 2


def test_response_shape_consistent() -> None:
    items: list[dict[str, object]] = []
    shape = LeanShape()
    result = apply_shape(items, shape=shape)
    assert set(result.keys()) == {"total", "count", "items"}
    assert result == {"total": 0, "count": 0, "items": []}


def test_shape_single_returns_dict_not_list() -> None:
    item = {"hostname": "fw1", "model": "PA-220", "uuid": "abc"}
    shape = LeanShape(default_fields=("hostname", "model"))
    result = shape_single(item, shape=shape)
    assert result == {"hostname": "fw1", "model": "PA-220"}
    assert not isinstance(result.get("items"), list)


def test_shape_single_handles_none_input() -> None:
    shape = LeanShape(default_fields=("hostname",))
    assert shape_single(None, shape=shape) == {}


def test_shape_single_drops_none_values() -> None:
    item = {"hostname": "fw1", "uptime": None}
    shape = LeanShape(default_fields=("hostname", "uptime"))
    assert shape_single(item, shape=shape) == {"hostname": "fw1"}


def test_token_efficiency_reduction_measurable() -> None:
    """Sanity check: a realistic verbose vs lean comparison shows >40% reduction."""
    # Mimic a security rule's verbose response with PAN-OS internals.
    verbose_item = {
        "name": "block-social-media",
        "fromzone": ["trust"],
        "tozone": ["untrust"],
        "source": ["any"],
        "destination": ["any"],
        "application": ["facebook", "twitter", "instagram"],
        "service": ["application-default"],
        "action": "deny",
        "disabled": False,
        "uuid": "12345678-1234-1234-1234-123456789012",
        "audit_comment": "Approved by SecOps 2024-08-15 ticket TKT-1234",
        "log_setting": "panorama-forward",
        "log_start": True,
        "log_end": True,
        "tag": ["compliance", "social-media", "v2"],
        "group_tag": "social-controls",
        "profile_setting": {"group": ["strict"]},
        "@_uuid": "internal-xxx",
        "@_dirtyId": "42",
        "@_loc": "vsys1",
    }
    shape = LeanShape(
        default_fields=(
            "name",
            "fromzone",
            "tozone",
            "source",
            "destination",
            "application",
            "service",
            "action",
            "disabled",
        ),
        extra_strip_keys=("@_uuid", "@_dirtyId", "@_loc"),
    )
    items = [verbose_item] * 50  # 50 rules

    verbose_result = apply_shape(items, shape=shape, verbose=True)
    lean_result = apply_shape(items, shape=shape)

    verbose_size = len(str(verbose_result))
    lean_size = len(str(lean_result))
    reduction_pct = 100 * (1 - lean_size / verbose_size)
    assert reduction_pct > 40, (
        f"Lean response should reduce size by >40% vs verbose; "
        f"got {reduction_pct:.1f}% (verbose={verbose_size}, lean={lean_size})"
    )
