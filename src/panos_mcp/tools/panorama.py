"""Panorama read tools.

Twenty tools for working with Panorama: managed devices, device groups,
templates, shared objects, pre/post rules, log collectors, push/commit
status, HA, and device-group hierarchy.

All these tools call ``client.op(...)`` or ``...refreshall(client)`` against
a Panorama target. They run unchanged against a Firewall target too — the
results are just empty when the target doesn't manage anything.
"""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.objects import (
    AddressGroup,
    AddressObject,
    SecurityProfileGroup,
    ServiceGroup,
    ServiceObject,
)
from panos.panorama import (
    DeviceGroup,
    Template,
    TemplateStack,
)
from panos.policies import (
    NatRule,
    PostRulebase,
    PreRulebase,
    SecurityRule,
)

from ..responses.schemas import (
    SHAPE_ADDRESS_GROUP,
    SHAPE_ADDRESS_OBJECT,
    SHAPE_COLLECTOR_GROUP,
    SHAPE_COMMIT_JOB,
    SHAPE_DEVICE_GROUP,
    SHAPE_LOG_COLLECTOR,
    SHAPE_MANAGED_DEVICE,
    SHAPE_NAT_RULE,
    SHAPE_PROFILE,
    SHAPE_PROFILE_GROUP,
    SHAPE_PUSH_STATUS,
    SHAPE_SECURITY_RULE,
    SHAPE_SERVICE_GROUP,
    SHAPE_SERVICE_OBJECT,
    SHAPE_TEMPLATE,
    SHAPE_TEMPLATE_STACK,
)
from ..responses.shapers import apply_shape
from ._common import ToolContext, op_to_dict, panos_object_dicts


def _entries(result: Any, *keys: str) -> list[dict[str, Any]]:
    """Walk a nested op result and return the entry list."""
    cursor: Any = result
    for k in keys:
        if not isinstance(cursor, dict):
            return []
        cursor = cursor.get(k, {})
    if isinstance(cursor, list):
        return [c for c in cursor if isinstance(c, dict)]
    if isinstance(cursor, dict):
        return [cursor]
    return []


def _find_dg(client: Any, name: str) -> DeviceGroup | None:
    """Look up a device group by name on a Panorama target."""
    for dg in DeviceGroup.refreshall(client):
        if dg.name == name:
            return dg
    return None


def register_panorama_tools(ctx: ToolContext) -> None:
    """Register the 20 Panorama read tools against ``ctx.mcp``."""

    # --- Managed devices & device groups ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_managed_devices(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Firewalls managed by Panorama with their connection status."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><devices><all></all></devices></show>")
        items = _entries(result, "devices", "entry") or _entries(result, "entry")
        return apply_shape(
            items, shape=SHAPE_MANAGED_DEVICE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_device_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Device groups configured in Panorama."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        dgs = DeviceGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(dgs), shape=SHAPE_DEVICE_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_device_group_hierarchy(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Device group parent-child hierarchy.

        Returns a flat list with each entry's ``name`` and ``parent_dg`` so
        the AI can reconstruct the tree client-side. Single-record response;
        ``verbose`` exposes additional metadata.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        dgs = DeviceGroup.refreshall(client)
        items = [
            {"name": dg.name, "parent_dg": getattr(dg, "parent_dg", None)} for dg in dgs
        ]
        return {"hierarchy": items, "count": len(items)}

    # --- Templates ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_templates(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Templates defined in Panorama."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        templates = Template.refreshall(client)
        return apply_shape(
            panos_object_dicts(templates), shape=SHAPE_TEMPLATE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_template_stacks(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Template stacks defined in Panorama."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        stacks = TemplateStack.refreshall(client)
        return apply_shape(
            panos_object_dicts(stacks), shape=SHAPE_TEMPLATE_STACK,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    # --- Shared objects ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_shared_address_objects(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Shared address objects at the Panorama level."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = AddressObject.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_ADDRESS_OBJECT,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_shared_address_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Shared address groups at the Panorama level."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = AddressGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_ADDRESS_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_shared_service_objects(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Shared service objects at the Panorama level."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = ServiceObject.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_SERVICE_OBJECT,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_shared_service_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Shared service groups at the Panorama level."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = ServiceGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_SERVICE_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_shared_security_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Security profiles at the Panorama level (read-only convenience)."""
        # Reuses the per-firewall security profile aggregator since the
        # behavior is the same when client is a Panorama instance.
        from .security import _security_profile_objects
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = _security_profile_objects(client)
        return apply_shape(
            items, shape=SHAPE_PROFILE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_shared_profile_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Shared security profile groups at the Panorama level."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        groups = SecurityProfileGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(groups), shape=SHAPE_PROFILE_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    # --- Pre/Post rules ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_pre_rules(
        device_group: str,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Pre-rules in a Panorama device group (pushed before local rules)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        dg = _find_dg(client, device_group)
        if dg is None:
            return {"error": f"Device group '{device_group}' not found.", "items": [], "total": 0, "count": 0}
        prerb = PreRulebase()
        dg.add(prerb)
        rules = SecurityRule.refreshall(prerb)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_SECURITY_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_post_rules(
        device_group: str,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Post-rules in a Panorama device group (pushed after local rules)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        dg = _find_dg(client, device_group)
        if dg is None:
            return {"error": f"Device group '{device_group}' not found.", "items": [], "total": 0, "count": 0}
        postrb = PostRulebase()
        dg.add(postrb)
        rules = SecurityRule.refreshall(postrb)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_SECURITY_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_device_group_nat_rules(
        device_group: str,
        rulebase: str = "pre",
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """NAT rules in a Panorama device group (rulebase: 'pre' or 'post')."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        if rulebase not in ("pre", "post"):
            return {"error": "rulebase must be 'pre' or 'post'.", "items": [], "total": 0, "count": 0}
        dg = _find_dg(client, device_group)
        if dg is None:
            return {"error": f"Device group '{device_group}' not found.", "items": [], "total": 0, "count": 0}
        rb = PreRulebase() if rulebase == "pre" else PostRulebase()
        dg.add(rb)
        rules = NatRule.refreshall(rb)
        return apply_shape(
            panos_object_dicts(rules), shape=SHAPE_NAT_RULE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    # --- Log collectors ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_log_collectors(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Log collector status from Panorama."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><log-collector><all></all></log-collector></show>")
        items = _entries(result, "log-collector", "entry") or _entries(result, "entry")
        return apply_shape(
            items, shape=SHAPE_LOG_COLLECTOR, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_collector_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Collector group configuration in Panorama."""
        # Not modeled in pan-os-python; pull via xpath show.
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']/log-collector-group"
        )
        result = op_to_dict(
            client, f"<show><config><running><xpath>{xpath}</xpath></running></config></show>"
        )
        groups = _entries(result, "log-collector-group", "entry")
        return apply_shape(
            groups, shape=SHAPE_COLLECTOR_GROUP, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    # --- Push & commit status ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_push_status(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Status of the most recent config push to managed devices."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client, "<show><config><push><status></status></push></config></show>"
        )
        items = _entries(result, "entry") or _entries(result, "devices", "entry")
        return apply_shape(
            items, shape=SHAPE_PUSH_STATUS, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_commit_status(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Status of recent commits (uses 'show jobs all')."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><jobs><all></all></jobs></show>")
        items = _entries(result, "job") or _entries(result, "entry")
        return apply_shape(
            items, shape=SHAPE_COMMIT_JOB, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    # --- Software / HA ---

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_managed_device_software(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Software and content versions on managed devices.

        Same op-command source as ``panorama_get_managed_devices``; the lean
        shape exposes version-relevant fields.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(client, "<show><devices><all></all></devices></show>")
        items = _entries(result, "devices", "entry") or _entries(result, "entry")
        # Override default whitelist to surface version columns specifically.
        from ..responses.shapers import LeanShape
        shape = LeanShape(
            default_fields=("hostname", "serial", "sw-version", "app-version", "threat-version", "wildfire-version"),
            name_field="hostname",
        )
        return apply_shape(
            items, shape=shape, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_get_ha_status(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Panorama high-availability status."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        result = op_to_dict(
            client,
            "<show><high-availability><state></state></high-availability></show>",
        )
        from ..responses.schemas import SHAPE_HA_STATUS
        from ..responses.shapers import shape_single
        return shape_single(result, shape=SHAPE_HA_STATUS, verbose=verbose, fields=fields)


__all__ = ["register_panorama_tools"]
