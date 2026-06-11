"""Benchmark: auditing a security policy.

Scenario: the AI is asked "audit this firewall's security policy — how many
allow vs deny rules, any any-any rules, any logging gaps". Two ways to
answer:

  A) Call get_security_rules() and let the AI compute the stats locally.
  B) Call summarize_security_policy() and read the structured answer.

This benchmark measures the token cost of both approaches on a 100-rule
policy and asserts that (B) is dramatically cheaper.
"""

from __future__ import annotations

import pytest
import tiktoken

from panos_mcp.responses.schemas import SHAPE_SECURITY_RULE
from panos_mcp.responses.shapers import apply_shape
from panos_mcp.tools.aggregations import _summarize_rules

from .conftest import count_tokens

pytestmark = pytest.mark.benchmark


def test_summarize_vs_lean_dump(
    tokenizer: tiktoken.Encoding,
    policy_100: list[dict[str, object]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """summarize_security_policy() should be 20x+ smaller than lean get_security_rules()."""
    lean_dump = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE)
    summary = _summarize_rules(policy_100)

    lean_tokens = count_tokens(tokenizer, lean_dump)
    summary_tokens = count_tokens(tokenizer, summary)
    ratio = lean_tokens / max(summary_tokens, 1)

    with capsys.disabled():
        print(
            f"\n  summarize_security_policy: {summary_tokens:>6,} tokens"
            f"\n  get_security_rules (lean): {lean_tokens:>6,} tokens"
            f"\n  ratio: {ratio:.1f}x smaller"
        )

    assert ratio >= 20, (
        f"summarize_security_policy regressed: only {ratio:.1f}x smaller than lean dump"
    )
    assert summary_tokens < 1_000, f"summary should fit in <1000 tokens; got {summary_tokens}"


def test_summarize_vs_verbose_dump(
    tokenizer: tiktoken.Encoding,
    policy_100: list[dict[str, object]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """summarize_security_policy() should be 50x+ smaller than verbose get_security_rules()."""
    verbose_dump = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE, verbose=True)
    summary = _summarize_rules(policy_100)

    verbose_tokens = count_tokens(tokenizer, verbose_dump)
    summary_tokens = count_tokens(tokenizer, summary)
    ratio = verbose_tokens / max(summary_tokens, 1)

    with capsys.disabled():
        print(
            f"\n  summarize_security_policy:    {summary_tokens:>6,} tokens"
            f"\n  get_security_rules (verbose): {verbose_tokens:>6,} tokens"
            f"\n  ratio: {ratio:.1f}x smaller"
        )

    assert ratio >= 50, (
        f"summarize_security_policy regressed: only {ratio:.1f}x smaller than verbose dump"
    )


def test_lean_dump_smaller_than_verbose(
    tokenizer: tiktoken.Encoding,
    policy_100: list[dict[str, object]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Lean default response should be ~40%+ smaller than verbose."""
    lean = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE)
    verbose = apply_shape(policy_100, shape=SHAPE_SECURITY_RULE, verbose=True)

    lean_tokens = count_tokens(tokenizer, lean)
    verbose_tokens = count_tokens(tokenizer, verbose)
    reduction = 100 * (1 - lean_tokens / verbose_tokens)

    with capsys.disabled():
        print(
            f"\n  verbose: {verbose_tokens:>6,} tokens"
            f"\n  lean:    {lean_tokens:>6,} tokens"
            f"\n  reduction: {reduction:.1f}%"
        )

    assert reduction >= 40, (
        f"lean default should reduce tokens by >=40% vs verbose; got {reduction:.1f}%"
    )
