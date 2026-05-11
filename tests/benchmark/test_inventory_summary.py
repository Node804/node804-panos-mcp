"""Benchmark: inventory snapshot.

Scenario: "give me an inventory snapshot of this firewall — how many
address objects, by what type; how many service objects; etc."

The aggregation tool ``count_objects_by_type`` answers in one structured
response. The alternative is dumping each object class separately and
letting the AI count.
"""

from __future__ import annotations

from typing import Any

import pytest
import tiktoken

from panos_mcp.responses.schemas import SHAPE_ADDRESS_OBJECT
from panos_mcp.responses.shapers import apply_shape

from .conftest import count_tokens

pytestmark = pytest.mark.benchmark


def _compute_count_by_type(addresses: list[dict[str, Any]]) -> dict[str, Any]:
    """Mirror count_objects_by_type's address-object slice for benchmarking."""
    by_type: dict[str, int] = {}
    for a in addresses:
        for key in ("ip_netmask", "ip_range", "fqdn", "ip_wildcard"):
            if a.get(key) is not None:
                kebab = key.replace("_", "-")
                by_type[kebab] = by_type.get(kebab, 0) + 1
                break
    return {
        "address_objects": {"total": len(addresses), "by_type": by_type},
    }


def test_count_objects_vs_address_dump(
    tokenizer: tiktoken.Encoding,
    addresses_500: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """count_objects_by_type slice should be 100x+ smaller than the address dump."""
    count_response = _compute_count_by_type(addresses_500)
    lean_dump = apply_shape(addresses_500, shape=SHAPE_ADDRESS_OBJECT)

    count_tokens_n = count_tokens(tokenizer, count_response)
    dump_tokens = count_tokens(tokenizer, lean_dump)
    ratio = dump_tokens / max(count_tokens_n, 1)

    with capsys.disabled():
        print(
            f"\n  count_objects_by_type (addresses slice): {count_tokens_n:>6,} tokens"
            f"\n  get_address_objects (lean dump):         {dump_tokens:>6,} tokens"
            f"\n  ratio: {ratio:.1f}x smaller"
        )

    assert ratio >= 100, (
        f"count_objects_by_type regressed: only {ratio:.1f}x smaller than address dump"
    )
    assert count_tokens_n < 100, (
        f"inventory snapshot should fit in <100 tokens; got {count_tokens_n}"
    )
