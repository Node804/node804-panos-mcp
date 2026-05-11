"""Security policy read + CRUD tools.

Phase 3 reads (Mode.READ): get_security_rules, get_security_profiles,
get_security_profile_groups, get_pbf_rules, get_dos_profiles, get_qos_rules.

Phase 5 CRUD (Mode.FULL):
  - Security rules: add, delete, move, set_disabled
  - PBF rules: add, delete, move, set_disabled
  - QoS rules: add, delete, move, set_disabled (via xapi — not modeled in
    pan-os-python 1.12.5)

Writes go to the candidate config — call ``commit`` (admin mode) to push
them to the running firewall.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.errors import PanDeviceError
from panos.policies import (
    PolicyBasedForwarding,
    PostRulebase,
    PreRulebase,
    Rulebase,
    SecurityRule,
)
from pydantic import Field

from ..responses.schemas import (
    SHAPE_DOS_PROFILE,
    SHAPE_PBF_RULE,
    SHAPE_PROFILE,
    SHAPE_PROFILE_GROUP,
    SHAPE_QOS_RULE,
    SHAPE_SECURITY_RULE,
)
from ..responses.shapers import apply_shape
from ._common import (
    ToolContext,
    op_to_dict,
    panos_object_dicts,
    wrap_panos_error,
    write_success,
)
from ._schemas import MemberList, MemberValue, PanosDescription, PanosName
from ._xml_writers import (
    QOS_RULES_XPATH,
    build_qos_rule_xml,
    qos_rule_xpath,
)

# ── Action enums ────────────────────────────────────────────────────────────

SecurityAction = Literal["allow", "deny", "drop", "reset-client", "reset-server", "reset-both"]
PbfAction = Literal["forward", "discard", "no-pbf"]
MoveWhere = Literal["top", "bottom", "before", "after"]
QosClass = Literal["1", "2", "3", "4", "5", "6", "7", "8"]


def _security_profile_objects(client: Any) -> list[dict[str, Any]]:
    """Aggregate the seven distinct security profile types into one list."""
    from panos.objects import (
        AntiSpywareProfile,
        AntivirusProfile,
        DataFilteringProfile,
        FileBlockingProfile,
        UrlFilteringProfile,
        VulnerabilityProfile,
        WildfireAnalysisProfile,
    )

    profile_types = [
        ("antivirus", AntivirusProfile),
        ("anti-spyware", AntiSpywareProfile),
        ("vulnerability", VulnerabilityProfile),
        ("url-filtering", UrlFilteringProfile),
        ("file-blocking", FileBlockingProfile),
        ("wildfire-analysis", WildfireAnalysisProfile),
        ("data-filtering", DataFilteringProfile),
    ]
    out: list[dict[str, Any]] = []
    for type_name, cls in profile_types:
        try:
            profiles = cls.refreshall(client)
        except Exception:
            continue
        for p in profiles:
            data = p.about()
            data["type"] = type_name
            out.append(data)
    return out


def _move_rule_object(
    obj: Any, where: str, dst: str | None, operation: str, name: str
) -> dict[str, Any]:
    """Apply pan-os-python's ``.move()`` with our standard error wrapping.

    ``where='before'`` or ``'after'`` requires ``dst`` (the reference rule
    name). For ``top`` and ``bottom``, dst is ignored.
    """
    if where in ("before", "after") and not dst:
        return {
            "success": False,
            "operation": operation,
            "name": name,
            "error": "'destination' is required when 'where' is 'before' or 'after'.",
        }
    try:
        if where in ("before", "after"):
            obj.move(location=where, ref=dst)
        else:
            obj.move(location=where)
    except PanDeviceError as e:
        return wrap_panos_error(e, operation, name)
    return write_success(operation, name, where=where, dst=dst)


def register_security_tools(ctx: ToolContext) -> None:
    """Register security/PBF/QoS read + CRUD tools against ``ctx.mcp``."""

    # ── Reads (Mode.READ) ───────────────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_security_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Security policy rulebase.

        Default response includes the fields most relevant to "what does this
        rule allow/deny": zones, source/destination, application/service,
        action, and disabled flag. Verbose adds profile groups, log settings,
        UUIDs, audit comments, and tags.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = SecurityRule.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_SECURITY_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_security_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """All security profiles (AV, anti-spyware, vulnerability, URL, etc.)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = _security_profile_objects(client)
        return apply_shape(
            items, shape=SHAPE_PROFILE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_security_profile_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Security profile groups that bundle multiple profiles for use in rules."""
        from panos.objects import SecurityProfileGroup
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        groups = SecurityProfileGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(groups), shape=SHAPE_PROFILE_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_pbf_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Policy-based forwarding rules."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = PolicyBasedForwarding.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_PBF_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_dos_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """DoS protection profiles."""
        try:
            from panos.network import DosProtectionProfile
        except ImportError:
            return {
                "error": (
                    "DoS profile model not available in this pan-os-python version. "
                    "Tracked for a follow-up; use get_config_xpath as a workaround."
                ),
                "items": [], "total": 0, "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        profiles = DosProtectionProfile.refreshall(client)
        _ = (PostRulebase, PreRulebase)
        return apply_shape(
            panos_object_dicts(profiles), shape=SHAPE_DOS_PROFILE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_qos_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """QoS policy rules. Read via xpath since pan-os-python doesn't model QoS."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client,
            f"<show><config><running><xpath>{QOS_RULES_XPATH}</xpath></running></config></show>",
        )
        rules_section = result.get("rules", result) if isinstance(result, dict) else {}
        if isinstance(rules_section, dict) and "entry" in rules_section:
            entries_raw = rules_section["entry"]
            items = entries_raw if isinstance(entries_raw, list) else [entries_raw]
        else:
            items = []
        return apply_shape(
            [i for i in items if isinstance(i, dict)],
            shape=SHAPE_QOS_RULE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    # ── Security rule CRUD (Mode.FULL) ──────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_security_rule(
        name: PanosName,
        from_zones: MemberList,
        to_zones: MemberList,
        source: MemberList,
        destination: MemberList,
        application: MemberList,
        service: MemberList,
        action: SecurityAction,
        description: PanosDescription | None = None,
        disabled: bool | None = None,
        log_start: bool | None = None,
        log_end: bool | None = None,
        profile_group: PanosName | None = None,
        tag: list[PanosName] | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a security policy rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = SecurityRule(
            name=name,
            fromzone=from_zones,
            tozone=to_zones,
            source=source,
            destination=destination,
            application=application,
            service=service,
            action=action,
            description=description,
            disabled=disabled,
            log_start=log_start,
            log_end=log_end,
            group=profile_group,
            tag=tag,
        )
        rulebase.add(rule)
        try:
            rule.create()
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_security_rule(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a security policy rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = SecurityRule(name=name)
        rulebase.add(rule)
        try:
            rule.delete()
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def move_security_rule(
        name: PanosName,
        where: MoveWhere,
        destination: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Move a security policy rule. Rule order determines evaluation priority.

        ``destination`` is the reference rule name; required when ``where`` is
        'before' or 'after'. Staged in candidate config.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = SecurityRule(name=name)
        rulebase.add(rule)
        return _move_rule_object(rule, where, destination, "moved", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def set_security_rule_disabled(
        name: PanosName,
        disabled: bool,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a security policy rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = SecurityRule(name=name, disabled=disabled)
        rulebase.add(rule)
        try:
            rule.update("disabled")
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_disabled", name)
        return write_success("set_disabled", name, disabled=disabled)

    # ── PBF rule CRUD (Mode.FULL) ───────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_pbf_rule(
        name: PanosName,
        from_zones: MemberList,
        source: MemberList,
        action: PbfAction,
        egress_interface: Annotated[
            str | None,
            Field(default=None, max_length=63, description="Egress interface for 'forward' action."),
        ] = None,
        next_hop_type: Literal["ip-address", "fqdn"] | None = None,
        next_hop_value: MemberValue | None = None,
        description: PanosDescription | None = None,
        disabled: bool | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a policy-based forwarding rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        kwargs: dict[str, Any] = {
            "name": name,
            "fromzone": from_zones,
            "source": source,
            "action": action,
            "description": description,
            "disabled": disabled,
        }
        if action == "forward":
            if egress_interface:
                kwargs["forward_egress_interface"] = egress_interface
            if next_hop_type and next_hop_value:
                # pan-os-python field is forward_next_hop_type / forward_next_hop_value
                kwargs["forward_next_hop_type"] = next_hop_type
                kwargs["forward_next_hop_value"] = next_hop_value
        rule = PolicyBasedForwarding(**{k: v for k, v in kwargs.items() if v is not None or k == "name"})
        rulebase.add(rule)
        try:
            rule.create()
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_pbf_rule(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a PBF rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = PolicyBasedForwarding(name=name)
        rulebase.add(rule)
        try:
            rule.delete()
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def move_pbf_rule(
        name: PanosName,
        where: MoveWhere,
        destination: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Move a PBF rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = PolicyBasedForwarding(name=name)
        rulebase.add(rule)
        return _move_rule_object(rule, where, destination, "moved", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def set_pbf_rule_disabled(
        name: PanosName,
        disabled: bool,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a PBF rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = PolicyBasedForwarding(name=name, disabled=disabled)
        rulebase.add(rule)
        try:
            rule.update("disabled")
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_disabled", name)
        return write_success("set_disabled", name, disabled=disabled)

    # ── QoS rule CRUD (Mode.FULL) — uses xapi since QoS not modeled ─────────

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_qos_rule(
        name: PanosName,
        from_zones: MemberList,
        to_zones: MemberList,
        source: MemberList,
        destination: MemberList,
        application: MemberList,
        service: MemberList,
        action_class: QosClass,
        description: PanosDescription | None = None,
        disabled: bool | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a QoS policy rule. Staged in candidate config.

        Falls back to xapi.set because pan-os-python 1.12.5 doesn't model
        QoS rules. XML construction uses defensive escaping.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        element = build_qos_rule_xml(
            name=name,
            from_zones=from_zones,
            to_zones=to_zones,
            source=source,
            destination=destination,
            application=application,
            service=service,
            action_class=action_class,
            description=description,
            disabled=disabled,
        )
        try:
            client.xapi.set(QOS_RULES_XPATH, element)
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_qos_rule(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a QoS rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        try:
            client.xapi.delete(qos_rule_xpath(name))
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def move_qos_rule(
        name: PanosName,
        where: MoveWhere,
        destination: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Move a QoS rule. Staged in candidate config."""
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
        try:
            client.xapi.move(
                qos_rule_xpath(name), where, dst=destination
            )
        except PanDeviceError as e:
            return wrap_panos_error(e, "move", name)
        return write_success("moved", name, where=where, dst=destination)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def set_qos_rule_disabled(
        name: PanosName,
        disabled: bool,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a QoS rule. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # Edit just the <disabled> element under the rule's xpath.
        disabled_xpath = f"{qos_rule_xpath(name)}/disabled"
        element = f"<disabled>{'yes' if disabled else 'no'}</disabled>"
        try:
            client.xapi.edit(disabled_xpath, element)
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_disabled", name)
        return write_success("set_disabled", name, disabled=disabled)


__all__ = ["register_security_tools"]
