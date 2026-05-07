"""Security policy read tools: rules, profiles, profile groups, PBF, DoS, QoS."""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.policies import (
    PolicyBasedForwarding,
    PostRulebase,
    PreRulebase,
    Rulebase,
    SecurityRule,
)

from ..responses.schemas import (
    SHAPE_DOS_PROFILE,
    SHAPE_PBF_RULE,
    SHAPE_PROFILE,
    SHAPE_PROFILE_GROUP,
    SHAPE_QOS_RULE,
    SHAPE_SECURITY_RULE,
)
from ..responses.shapers import apply_shape
from ._common import ToolContext, panos_object_dicts


def _security_profile_objects(client: Any) -> list[dict[str, Any]]:
    """Aggregate the seven distinct security profile types into one list.

    Each profile type (antivirus, anti-spyware, vulnerability, url-filtering,
    file-blocking, wildfire-analysis, data-filtering) lives at a different
    XPath. We surface them with a ``type`` field so the AI can filter.
    """
    from panos.objects import (
        AntiSpywareProfile,
        AntivirusProfile,
        DataFilteringProfile,
        FileBlockingProfile,
        SecurityProfileGroup,  # noqa: F401  # imported for completeness
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


def register_security_tools(ctx: ToolContext) -> None:
    """Register the six security-policy read tools against ``ctx.mcp``."""

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
        """All security profiles (AV, anti-spyware, vulnerability, URL, etc.).

        Profiles from the seven types are returned in one list with a
        ``type`` field distinguishing them. Use ``pattern`` to find profiles
        by name across types.
        """
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
        # pan-os-python doesn't model DoS profiles directly; refresh via op.
        # As a stopgap we attempt to import the class; if missing, return a
        # clear error rather than crash.
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
        # Forward to silence lint
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
        """QoS policy rules.

        QoS rules aren't modeled in pan-os-python — read via op-style xpath.
        """
        from ._common import op_to_dict
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
            "/rulebase/qos/rules"
        )
        result = op_to_dict(
            client, f"<show><config><running><xpath>{xpath}</xpath></running></config></show>"
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


__all__ = ["register_security_tools"]
