"""NAT policy read + CRUD tools.

Phase 3 reads (Mode.READ): get_nat_rules.
Phase 5 CRUD (Mode.FULL): add/delete/move/set_disabled.
"""

from __future__ import annotations

from typing import Any, Literal

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.errors import PanDeviceError
from panos.policies import NatRule, Rulebase

from ..responses.schemas import SHAPE_NAT_RULE
from ..responses.shapers import apply_shape
from ._common import (
    ToolContext,
    panos_object_dicts,
    redirect_panorama_to_sibling,
    wrap_panos_error,
    write_success,
)
from ._schemas import MemberList, MemberValue, PanosDescription, PanosName

SnatType = Literal["dynamic-ip-and-port", "dynamic-ip", "static-ip"]
MoveWhere = Literal["top", "bottom", "before", "after"]


def register_nat_tools(ctx: ToolContext) -> None:
    """Register NAT read + CRUD tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_nat_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """NAT policy rules (source NAT, destination NAT, bidirectional), firewall-scoped.

        Reads the firewall's local NAT rulebase. On a Panorama target it returns
        an error pointing to the device-group tools rather than an empty list.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = redirect_panorama_to_sibling(
            client,
            "get_nat_rules",
            use=(
                "panorama_get_device_group_nat_rules (or panorama_get_pre_rules / "
                "panorama_get_post_rules with rule_type='nat'), per device group"
            ),
        )
        if guard is not None:
            return guard
        rulebase = Rulebase()
        client.add(rulebase)
        rules = NatRule.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules),
            shape=SHAPE_NAT_RULE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_nat_rule(
        name: PanosName,
        from_zones: MemberList,
        to_zones: MemberList,
        source: MemberList,
        destination: MemberList,
        service: MemberValue = "any",
        snat_type: SnatType | None = None,
        snat_address: MemberValue | None = None,
        snat_interface: PanosName | None = None,
        dnat_address: MemberValue | None = None,
        dnat_port: MemberValue | None = None,
        description: PanosDescription | None = None,
        disabled: bool | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a NAT policy rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        kwargs: dict[str, Any] = {
            "name": name,
            "fromzone": from_zones,
            "tozone": to_zones,
            "source": source,
            "destination": destination,
            "service": service,
            "description": description,
            "disabled": disabled,
        }
        if snat_type:
            kwargs["source_translation_type"] = snat_type
            if snat_address:
                kwargs["source_translation_translated_addresses"] = [snat_address]
            if snat_interface and snat_type == "dynamic-ip-and-port":
                kwargs["source_translation_interface"] = snat_interface
        if dnat_address:
            kwargs["destination_translated_address"] = dnat_address
            if dnat_port:
                kwargs["destination_translated_port"] = dnat_port
        rule = NatRule(**{k: v for k, v in kwargs.items() if v is not None or k == "name"})
        rulebase.add(rule)
        try:
            rule.create()
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_nat_rule(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a NAT policy rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = NatRule(name=name)
        rulebase.add(rule)
        try:
            rule.delete()
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def move_nat_rule(
        name: PanosName,
        where: MoveWhere,
        destination: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Move a NAT rule. Staged in candidate config."""
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
        rule = NatRule(name=name)
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
    async def set_nat_rule_disabled(
        name: PanosName,
        disabled: bool,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a NAT rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = NatRule(name=name, disabled=disabled)
        rulebase.add(rule)
        try:
            rule.update("disabled")
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_disabled", name)
        return write_success("set_disabled", name, disabled=disabled)


__all__ = ["register_nat_tools"]
