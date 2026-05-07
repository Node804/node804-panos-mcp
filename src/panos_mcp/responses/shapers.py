"""Response-shaping pipeline for token-efficient tool responses.

Every read tool that returns a list of items runs the same pipeline:

1. **Filter** by ``pattern`` if the caller supplied one (server-side
   substring match on the name field — vastly cheaper than dumping the
   whole inventory and asking the AI to grep).
2. **Whitelist** fields based on the tool's :class:`LeanShape`:
   - ``fields=[...]`` (caller override): keep exactly those fields
   - ``verbose=True``: keep everything
   - default: keep only ``shape.default_fields``
3. **Drop ``None`` values** — PAN-OS objects expose dozens of optional
   fields; ``None`` carries zero signal but real token cost.
4. **Paginate** with ``pagination`` (defaults: ``limit=100``, ``offset=0``).

The function returns ``{total, count, items}`` so the AI can tell when
results were truncated and whether it should ``offset`` for more.

Single-item responses use :func:`shape_single` instead.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from mcp_toolkit import Pagination, filter_by_pattern, paginate


@dataclass(frozen=True)
class LeanShape:
    """Per-tool token-efficiency configuration.

    Keep one of these per read tool in :mod:`panos_mcp.responses.schemas`,
    so all field whitelists live in one place and are easy to audit.
    """

    default_fields: tuple[str, ...] = ()
    """Fields included when ``verbose=False`` and ``fields=None``.

    An empty tuple means "include all fields" (i.e. lean shaping degenerates
    to drop-None only). Useful for op-command responses where fields are
    already terse and a per-field whitelist is overkill.
    """

    drop_when_none: bool = True
    """Drop ``None`` values from each item.

    PAN-OS objects expose many optional fields; ``None`` means "not
    configured" which is rarely interesting to the AI. Setting this False
    preserves None values so the caller can distinguish "absent" from
    "explicitly null".
    """

    name_field: str = "name"
    """Field used by the pattern filter. Most PAN-OS objects use 'name'."""

    extra_strip_keys: tuple[str, ...] = field(default_factory=tuple)
    """Keys to drop unconditionally (e.g. PAN-OS internal flags from XML responses).

    Applied recursively. Useful when ``.about()`` exposes fields like
    ``@_uuid``, ``@_dirtyId``, ``@_loc`` that the AI never reasons over.
    """


def _project_fields(
    item: Mapping[str, Any],
    fields: Iterable[str] | None,
    default_fields: tuple[str, ...],
    verbose: bool,
) -> dict[str, Any]:
    """Apply field whitelisting per the shape rules."""
    if fields is not None:
        keep = set(fields)
        return {k: v for k, v in item.items() if k in keep}
    if verbose or not default_fields:
        return dict(item)
    keep = set(default_fields)
    return {k: v for k, v in item.items() if k in keep}


def _drop_nones(item: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if v is not None}


def _strip_keys_recursive(value: Any, drop: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: _strip_keys_recursive(v, drop) for k, v in value.items() if k not in drop}
    if isinstance(value, list):
        return [_strip_keys_recursive(v, drop) for v in value]
    return value


def apply_shape(
    items: Iterable[Mapping[str, Any]],
    *,
    shape: LeanShape,
    verbose: bool = False,
    fields: list[str] | None = None,
    pagination: Pagination | None = None,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Run the full shaping pipeline on a list of items.

    Returns ``{total, count, items}``:
        - ``total`` — items remaining after pattern filter (pre-pagination)
        - ``count`` — items in the returned page
        - ``items`` — the shaped, filtered, paginated list
    """
    # Strip unconditionally first; protects against case where strip_keys
    # contains the name_field (rare but possible misconfig).
    materialized: list[Mapping[str, Any]] = list(items)
    if shape.extra_strip_keys:
        drop = set(shape.extra_strip_keys)
        materialized = [_strip_keys_recursive(item, drop) for item in materialized]

    # Pattern filter on the original (post-strip) items.
    filtered = filter_by_pattern(materialized, pattern, name_field=shape.name_field)
    total = len(filtered)

    # Project + drop-None.
    projected = [
        _project_fields(item, fields, shape.default_fields, verbose) for item in filtered
    ]
    if shape.drop_when_none:
        projected = [_drop_nones(item) for item in projected]

    # Paginate.
    if pagination is not None:
        page = paginate(projected, pagination.limit, pagination.offset)
    else:
        page = projected

    return {
        "total": total,
        "count": len(page),
        "items": page,
    }


def shape_single(
    item: Mapping[str, Any] | None,
    *,
    shape: LeanShape,
    verbose: bool = False,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Apply whitelist + drop-None to a single item.

    Use for tools that return one record (e.g. ``get_firewall_info``).
    Pattern filter and pagination don't apply. Returns ``{}`` for ``None``
    input so callers can chain without null checks.
    """
    if item is None:
        return {}

    if shape.extra_strip_keys:
        item = _strip_keys_recursive(item, set(shape.extra_strip_keys))

    projected = _project_fields(item, fields, shape.default_fields, verbose)
    if shape.drop_when_none:
        projected = _drop_nones(projected)
    return projected


__all__ = ["LeanShape", "apply_shape", "shape_single"]
