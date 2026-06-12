"""NAT policy read tool."""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.policies import NatRule, Rulebase

from ..responses.schemas import SHAPE_NAT_RULE
from ..responses.shapers import apply_shape
from ._common import ToolContext, panos_object_dicts


def register_nat_tools(ctx: ToolContext) -> None:
    """Register the NAT read tool against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_nat_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """NAT policy rules (source NAT, destination NAT, bidirectional)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = NatRule.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_NAT_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )


__all__ = ["register_nat_tools"]
