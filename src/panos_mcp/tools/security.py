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

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from pan.xapi import PanXapiError
from panos.errors import PanDeviceError
from panos.policies import (
    PolicyBasedForwarding,
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
    AttrFilter,
    ToolContext,
    check_renamed_attr_keys,
    config_xpath_to_dict,
    enrich_security_rule_dicts,
    filter_by_attrs,
    gather_scoped_objects,
    panos_object_dicts,
    read_timeout,
    redirect_panorama_to_sibling,
    run_blocking_timeout,
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


# Threat security profiles (antivirus, anti-spyware, vulnerability, etc.) are
# not modeled as classes by pan-os-python 1.12.5 — ``panos.objects`` only
# exposes ``SecurityProfileGroup`` and ``LogForwardingProfile``. So we read
# them straight from the XML config. Each tuple maps the friendly type name we
# report to the XML element name under the ``profiles`` node.
_PROFILE_XML_TYPES = (
    ("antivirus", "virus"),
    ("anti-spyware", "spyware"),
    ("vulnerability", "vulnerability"),
    ("url-filtering", "url-filtering"),
    ("file-blocking", "file-blocking"),
    ("wildfire-analysis", "wildfire-analysis"),
    ("data-filtering", "data-filtering"),
)


def _profiles_xpath(client: Any) -> str:
    """Config xpath of the ``profiles`` node for a Firewall or Panorama target.

    Panorama shared profiles live at ``/config/shared/profiles``; a firewall's
    live under its vsys. We never raise here — an unexpected client type falls
    back to the shared path, which simply returns no entries on a firewall.
    """
    from panos.base import Root
    from panos.panorama import Panorama

    if isinstance(client, Panorama):
        return "/config/shared/profiles"
    vsys = getattr(client, "vsys", None) or "vsys1"
    return f"{client.xpath_root(Root.VSYS, vsys)}/profiles"


def _flatten_security_profiles(profiles: Any) -> list[dict[str, Any]]:
    """Flatten a ``profiles`` config subtree into ``{name, type, ...}`` dicts."""
    if not isinstance(profiles, dict):
        return []
    out: list[dict[str, Any]] = []
    for type_name, xml_tag in _PROFILE_XML_TYPES:
        node = profiles.get(xml_tag)
        if not isinstance(node, dict):
            continue
        entries = node.get("entry")
        if entries is None:
            continue
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = dict(entry)
            # element_to_dict stores the entry's name attribute as "@_name".
            data["name"] = data.pop("@_name", None)
            data["type"] = type_name
            out.append(data)
    return out


def _security_profiles_at_xpath(client: Any, xpath: str) -> list[dict[str, Any]]:
    """Read + flatten the security ``profiles`` subtree at a specific xpath.

    Treats PAN-OS "No such node" (nothing configured at this scope) as an
    empty list; re-raises other errors.
    """
    try:
        result = config_xpath_to_dict(client, xpath)
    except (PanDeviceError, PanXapiError) as exc:
        # PAN-OS doesn't materialize empty config subtrees, so an absent
        # ``profiles`` node returns ``<msg>No such node</msg>`` (raised by
        # pan-python). That's the same "empty" signal as a present-but-childless
        # node — surface it as [] rather than a misleading tool error.
        if "no such node" in str(exc).lower():
            return []
        raise
    return _flatten_security_profiles(result.get("profiles"))


def _security_profile_objects(client: Any) -> list[dict[str, Any]]:
    """Aggregate the seven security profile types at the target's default scope.

    Firewall → vsys; Panorama → shared. (For a full Panorama walk across
    device groups, ``get_security_profiles`` orchestrates per-scope reads.)
    """
    return _security_profiles_at_xpath(client, _profiles_xpath(client))


def _dg_profiles_xpath(dg_name: str) -> str:
    """Running-config xpath of a device group's security ``profiles`` subtree."""
    return (
        "/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{dg_name}']/profiles"
    )


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
        attrs: AttrFilter = None,
    ) -> dict[str, Any]:
        """Security policy rulebase.

        Default response includes the fields most relevant to "what does this
        rule allow/deny": zones, source/destination, application/service,
        action, and disabled flag — plus two derived audit booleans:
        ``has_inspection`` (true when a profile group is bound OR any
        individual L7 profile — ``virus``, ``spyware``, ``vulnerability``,
        ``url_filtering``, ``file_blocking``, ``data_filtering``,
        ``wildfire_analysis`` — is attached) and ``has_log_setting`` (true
        when a log forwarding profile is attached). Verbose adds the raw
        underlying fields (``group``, the individual profile keys,
        ``log_setting``, ``log_start``/``log_end``) plus UUIDs, audit
        comments, and tags.

        Use ``attrs`` for server-side filtering on rule attributes other than
        name — e.g. ``{"source": "10.0.0.0/24"}`` or
        ``{"application": "any", "has_inspection": "false"}``. Filtering
        server-side is dramatically cheaper than fetching the full rulebase
        and post-filtering, especially for audits over large policies.
        """
        renamed = check_renamed_attr_keys(attrs)
        if renamed is not None:
            return renamed
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = redirect_panorama_to_sibling(
            client,
            "get_security_rules",
            use=(
                "panorama_get_pre_rules / panorama_get_post_rules with "
                "rule_type='security' (per device group)"
            ),
        )
        if guard is not None:
            return guard
        rulebase = Rulebase()
        client.add(rulebase)
        rules = SecurityRule.refreshall(rulebase)
        # Enrichment runs first so attrs can match against derived booleans
        # (``has_inspection``, ``has_log_setting``) and the coerced ``disabled``.
        # The attribute filter runs before ``apply_shape`` so callers can
        # filter on verbose-only fields (e.g. ``source``) without flipping
        # ``verbose=true`` just to get the haystack into the response.
        enriched = enrich_security_rule_dicts(panos_object_dicts(rules))
        filtered = filter_by_attrs(enriched, attrs)
        return apply_shape(
            filtered,
            shape=SHAPE_SECURITY_RULE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_security_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """All security profiles (AV, anti-spyware, vulnerability, URL, etc.).

        Scope-aware: on a firewall this reads vsys1; on a Panorama it walks
        ``shared`` plus every device group's profile tree, tagging each profile
        with its ``scope`` so device-group profiles aren't silently omitted.
        Each per-scope read is bounded; a scope that times out is skipped and
        listed in ``timed_out``.
        """
        from panos.panorama import DeviceGroup, Panorama

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        timeout_s = read_timeout()
        rows: list[dict[str, Any]]
        timed_out: list[str] = []
        if isinstance(client, Panorama):
            rows = []
            try:
                dgs = await run_blocking_timeout(timeout_s, DeviceGroup.refreshall, client)
            except TimeoutError:
                return {
                    "error": (
                        f"get_security_profiles timed out after {timeout_s:g}s "
                        "enumerating device groups; retry or check reachability."
                    ),
                    "items": [],
                    "total": 0,
                    "count": 0,
                }
            targets = [("shared", "/config/shared/profiles")]
            targets += [(dg.name, _dg_profiles_xpath(dg.name)) for dg in dgs]
            for scope_label, xpath in targets:
                try:
                    profs = await run_blocking_timeout(
                        timeout_s, _security_profiles_at_xpath, client, xpath
                    )
                except TimeoutError:
                    timed_out.append(scope_label)
                    continue
                for p in profs:
                    p["scope"] = scope_label
                    rows.append(p)
        else:
            rows = await run_blocking_timeout(timeout_s, _security_profile_objects, client)
        out = apply_shape(
            rows,
            shape=SHAPE_PROFILE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_security_profile_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Security profile groups that bundle multiple profiles for use in rules.

        Scope-aware on Panorama (shared + every device group, tagged by
        ``scope``); reads vsys1 on a firewall.
        """
        from panos.objects import SecurityProfileGroup

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rows, timed_out = await gather_scoped_objects(
            client, SecurityProfileGroup, timeout=read_timeout()
        )
        out = apply_shape(
            rows,
            shape=SHAPE_PROFILE_GROUP,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        return out

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_pbf_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Policy-based forwarding rules, firewall-scoped.

        On a Panorama target this returns an error pointing to the device-group
        tools rather than an empty list.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = redirect_panorama_to_sibling(
            client,
            "get_pbf_rules",
            use=(
                "panorama_get_pre_rules / panorama_get_post_rules with "
                "rule_type='pbf' (per device group)"
            ),
        )
        if guard is not None:
            return guard
        rulebase = Rulebase()
        client.add(rulebase)
        rules = PolicyBasedForwarding.refreshall(rulebase)
        return apply_shape(
            panos_object_dicts(rules),
            shape=SHAPE_PBF_RULE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
                "items": [],
                "total": 0,
                "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        profiles = DosProtectionProfile.refreshall(client)
        return apply_shape(
            panos_object_dicts(profiles),
            shape=SHAPE_DOS_PROFILE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_qos_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """QoS policy rules, firewall-scoped. Read via xpath since pan-os-python doesn't model QoS.

        Reads the firewall's local QoS rulebase. On a Panorama target that path
        doesn't exist (the raw query errors with "No such node"), so this
        returns a clean error instead — there is no Panorama device-group QoS
        tool; query a managed firewall directly or use get_config_xpath against
        the device group's QoS rulebase.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = redirect_panorama_to_sibling(
            client,
            "get_qos_rules",
            use=(
                "a managed firewall (pass firewall=), or get_config_xpath against the "
                "device group's QoS rulebase — QoS is not exposed as a Panorama tool"
            ),
        )
        if guard is not None:
            return guard
        result = config_xpath_to_dict(client, QOS_RULES_XPATH)
        rules_section = result.get("rules", result) if isinstance(result, dict) else {}
        if isinstance(rules_section, dict) and "entry" in rules_section:
            entries_raw = rules_section["entry"]
            items = entries_raw if isinstance(entries_raw, list) else [entries_raw]
        else:
            items = []
        return apply_shape(
            [i for i in items if isinstance(i, dict)],
            shape=SHAPE_QOS_RULE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
            Field(
                default=None, max_length=63, description="Egress interface for 'forward' action."
            ),
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
        rule = PolicyBasedForwarding(
            **{k: v for k, v in kwargs.items() if v is not None or k == "name"}
        )
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
            client.xapi.move(qos_rule_xpath(name), where, dst=destination)
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
