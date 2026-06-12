"""Certificate read tools: certificates, decryption rules, decryption profiles."""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag

from ..responses.schemas import (
    SHAPE_CERTIFICATE,
    SHAPE_DECRYPTION_PROFILE,
    SHAPE_DECRYPTION_RULE,
)
from ..responses.shapers import apply_shape
from ._common import ToolContext, panos_object_dicts


def register_certificates_tools(ctx: ToolContext) -> None:
    """Register the three certificate-related read tools."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_certificates(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """SSL/TLS certificates configured on the firewall."""
        try:
            from panos.device import Certificate
        except ImportError:
            return {
                "error": "Certificate model not in this pan-os-python version.",
                "items": [],
                "total": 0,
                "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        certs = Certificate.refreshall(client)
        return apply_shape(
            panos_object_dicts(certs),
            shape=SHAPE_CERTIFICATE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_decryption_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """SSL decryption policy rules."""
        try:
            from panos.policies import DecryptionRule, Rulebase
        except ImportError:
            return {
                "error": "DecryptionRule not modeled in this pan-os-python version.",
                "items": [],
                "total": 0,
                "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = DecryptionRule.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules),
            shape=SHAPE_DECRYPTION_RULE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_decryption_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """SSL decryption profiles."""
        try:
            from panos.objects import DecryptionProfile
        except ImportError:
            return {
                "error": "DecryptionProfile not modeled in this pan-os-python version.",
                "items": [],
                "total": 0,
                "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        profiles = DecryptionProfile.refreshall(client)
        return apply_shape(
            panos_object_dicts(profiles),
            shape=SHAPE_DECRYPTION_PROFILE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )


__all__ = ["register_certificates_tools"]
