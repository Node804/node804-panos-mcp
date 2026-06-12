"""Administrator read tools: admin accounts, role definitions, auth profiles."""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.device import Administrator, AuthenticationProfile

from ..responses.schemas import SHAPE_ADMIN, SHAPE_ADMIN_ROLE, SHAPE_AUTH_PROFILE
from ..responses.shapers import apply_shape
from ._common import ToolContext, op_to_dict, panos_object_dicts


def register_admin_tools(ctx: ToolContext) -> None:
    """Register the three admin read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_admins(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Administrator accounts configured on the firewall."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        admins = Administrator.refreshall(client)
        return apply_shape(
            panos_object_dicts(admins), shape=SHAPE_ADMIN,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_admin_roles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Administrator role definitions and their permission sets."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # pan-os-python doesn't model admin-role directly; fall back to op-style
        # config read via show.
        result = op_to_dict(
            client,
            "<show><config><running><xpath>/config/devices/entry/vsys/entry[@name='vsys1']"
            "/admin-role</xpath></running></config></show>",
        )
        # The result wraps in <admin-role><entry>...</entry></admin-role>; flatten.
        admin_role = result.get("admin-role", result) if isinstance(result, dict) else result
        if isinstance(admin_role, dict) and "entry" in admin_role:
            entries = admin_role["entry"]
            items = entries if isinstance(entries, list) else [entries]
        else:
            items = []
        return apply_shape(
            items, shape=SHAPE_ADMIN_ROLE, verbose=verbose, fields=fields,
            pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_auth_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Authentication profiles (RADIUS, LDAP, TACACS+, local DB)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        profiles = AuthenticationProfile.refreshall(client)
        return apply_shape(
            panos_object_dicts(profiles), shape=SHAPE_AUTH_PROFILE,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )


__all__ = ["register_admin_tools"]
