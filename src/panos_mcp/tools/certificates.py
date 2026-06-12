"""Certificates + decryption read & CRUD tools.

Phase 3 reads (Mode.READ): get_certificates, get_decryption_rules,
get_decryption_profiles.
Phase 5 CRUD (Mode.FULL): add/delete/move/set_disabled for decryption rules.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.errors import PanDeviceError

from ..responses.schemas import (
    SHAPE_CERTIFICATE,
    SHAPE_DECRYPTION_PROFILE,
    SHAPE_DECRYPTION_RULE,
)
from ..responses.shapers import apply_shape
from ._common import ToolContext, panos_object_dicts, wrap_panos_error, write_success
from ._schemas import MemberList, PanosDescription, PanosName

DecryptionAction = Literal["decrypt", "no-decrypt"]
DecryptionType = Literal["ssl-forward-proxy", "ssh-proxy", "ssl-inbound-inspection"]
MoveWhere = Literal["top", "bottom", "before", "after"]


def register_certificates_tools(ctx: ToolContext) -> None:
    """Register certificate read + decryption rule CRUD tools."""

    # ── Reads (Mode.READ) ───────────────────────────────────────────────────

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
                "items": [], "total": 0, "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        certs = Certificate.refreshall(client)
        return apply_shape(
            panos_object_dicts(certs), shape=SHAPE_CERTIFICATE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
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
        from panos.policies import DecryptionRule, Rulebase
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = DecryptionRule.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_DECRYPTION_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
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
                "items": [], "total": 0, "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        profiles = DecryptionProfile.refreshall(client)
        return apply_shape(
            panos_object_dicts(profiles), shape=SHAPE_DECRYPTION_PROFILE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    # ── Decryption rule CRUD (Mode.FULL) ────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_decryption_rule(
        name: PanosName,
        from_zones: MemberList,
        to_zones: MemberList,
        source: MemberList,
        destination: MemberList,
        service: MemberList,
        action: DecryptionAction,
        type: DecryptionType | None = None,
        decryption_profile: PanosName | None = None,
        description: PanosDescription | None = None,
        disabled: bool | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create an SSL decryption policy rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        # pan-os-python's DecryptionRule uses different param names than
        # SecurityRule/NatRule. Map our consistent tool inputs to its schema.
        kwargs: dict[str, Any] = {
            "name": name,
            "source_zones": from_zones,
            "destination_zones": to_zones,
            "source_addresses": source,
            "destination_addresses": destination,
            "services": service,
            "action": action,
            "description": description,
            "disabled": disabled,
        }
        if type:
            kwargs["decryption_type"] = type
        if decryption_profile:
            kwargs["decryption_profile"] = decryption_profile
        rule = DecryptionRule(**{k: v for k, v in kwargs.items() if v is not None or k == "name"})
        rulebase.add(rule)
        try:
            rule.create()
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_decryption_rule(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a decryption rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = DecryptionRule(name=name)
        rulebase.add(rule)
        try:
            rule.delete()
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def move_decryption_rule(
        name: PanosName,
        where: MoveWhere,
        destination: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Move a decryption rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        if where in ("before", "after") and not destination:
            return {
                "success": False,
                "operation": "moved",
                "name": name,
                "error": "'destination' is required when 'where' is 'before' or 'after'.",
            }
        rulebase = Rulebase()
        client.add(rulebase)
        rule = DecryptionRule(name=name)
        rulebase.add(rule)
        try:
            if where in ("before", "after"):
                rule.move(location=where, ref=destination)
            else:
                rule.move(location=where)
        except PanDeviceError as e:
            return wrap_panos_error(e, "move", name)
        return write_success("moved", name, where=where, dst=destination)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def set_decryption_rule_disabled(
        name: PanosName,
        disabled: bool,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a decryption rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = DecryptionRule(name=name, disabled=disabled)
        rulebase.add(rule)
        try:
            rule.update("disabled")
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_disabled", name)
        return write_success("set_disabled", name, disabled=disabled)


__all__ = ["register_certificates_tools"]
