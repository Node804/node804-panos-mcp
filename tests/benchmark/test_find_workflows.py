"""Benchmark: find workflows.

Scenarios:
  1. "Where is 10.0.0.5 defined?" — find_address_object(ip) vs dumping
     all address objects and letting the AI filter.
  2. "Find rules matching 'block-tor'" — find_rule_by_name(pattern) vs
     dumping all rules and letting the AI grep.
"""

from __future__ import annotations

import pytest
import tiktoken

from panos_mcp.responses.schemas import SHAPE_ADDRESS_OBJECT, SHAPE_SECURITY_RULE
from panos_mcp.responses.shapers import apply_shape
from panos_mcp.tools.aggregations import _filter_address_objects_by_query

from .conftest import count_tokens

pytestmark = pytest.mark.benchmark


def test_find_address_object_vs_dump(
    tokenizer: tiktoken.Encoding,
    addresses_500: list[dict[str, object]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """find_address_object('10.0.0.5') should be 50x+ smaller than the inventory dump."""
    matches, _ = _filter_address_objects_by_query(addresses_500, "10.0.0.5")
    find_response = {
        "query": "10.0.0.5",
        "strategy": "ip",
        "count": len(matches),
        "matches": matches,
    }
    lean_dump = apply_shape(addresses_500, shape=SHAPE_ADDRESS_OBJECT)

    find_tokens = count_tokens(tokenizer, find_response)
    dump_tokens = count_tokens(tokenizer, lean_dump)
    ratio = dump_tokens / max(find_tokens, 1)

    with capsys.disabled():
        print(
            f"\n  find_address_object('10.0.0.5'): {find_tokens:>6,} tokens "
            f"({len(matches)} matches)"
            f"\n  get_address_objects (lean dump): {dump_tokens:>6,} tokens "
            f"({len(addresses_500)} objects)"
            f"\n  ratio: {ratio:.1f}x smaller"
        )

    assert ratio >= 50, (
        f"find_address_object regressed: only {ratio:.1f}x smaller than dump"
    )


def test_find_rule_by_name_vs_dump(
    tokenizer: tiktoken.Encoding,
    policy_100: list[dict[str, object]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """find_rule_by_name('rule-001') should be 10x+ smaller than a full rule dump."""
    needle = "rule-001"
    matches = [
        {**r, "type": "security"}
        for r in policy_100
        if isinstance(r.get("name"), str)
        and needle in str(r["name"]).casefold()
    ]
    find_response = {"pattern": needle, "count": len(matches), "matches": matches}
    lean_dump = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE)

    find_tokens = count_tokens(tokenizer, find_response)
    dump_tokens = count_tokens(tokenizer, lean_dump)
    ratio = dump_tokens / max(find_tokens, 1)

    with capsys.disabled():
        print(
            f"\n  find_rule_by_name('rule-001'): {find_tokens:>6,} tokens "
            f"({len(matches)} matches)"
            f"\n  get_security_rules (lean):     {dump_tokens:>6,} tokens "
            f"({len(policy_100)} rules)"
            f"\n  ratio: {ratio:.1f}x smaller"
        )

    assert ratio >= 10, (
        f"find_rule_by_name regressed: only {ratio:.1f}x smaller than dump"
    )


def test_pattern_param_on_get_security_rules(
    tokenizer: tiktoken.Encoding,
    policy_100: list[dict[str, object]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Server-side pattern filter on get_security_rules saves vs full dump.

    Even before aggregation tools, the built-in pattern filter is a big
    token win — the AI doesn't have to dump and grep client-side.
    """
    filtered = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE, pattern="rule-00")
    full = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE)

    filtered_tokens = count_tokens(tokenizer, filtered)
    full_tokens = count_tokens(tokenizer, full)
    ratio = full_tokens / max(filtered_tokens, 1)

    with capsys.disabled():
        print(
            f"\n  get_security_rules(pattern='rule-00'): {filtered_tokens:>6,} tokens "
            f"({filtered['count']} matches)"
            f"\n  get_security_rules (no filter):        {full_tokens:>6,} tokens "
            f"({full['count']} rules)"
            f"\n  ratio: {ratio:.1f}x smaller"
        )

    assert ratio >= 5, (
        f"pattern filter should be >=5x smaller; got {ratio:.1f}x"
    )
