"""Object read tools: address objects/groups, service objects/groups, app filters, tags."""

from __future__ import annotations

from typing import Any

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.objects import (
    AddressGroup,
    AddressObject,
    ApplicationFilter,
    ServiceGroup,
    ServiceObject,
    Tag,
)

from ..responses.schemas import (
    SHAPE_ADDRESS_GROUP,
    SHAPE_ADDRESS_OBJECT,
    SHAPE_APPLICATION_FILTER,
    SHAPE_SERVICE_GROUP,
    SHAPE_SERVICE_OBJECT,
    SHAPE_TAG,
)
from ..responses.shapers import apply_shape
from ._common import ToolContext, panos_object_dicts


def register_objects_tools(ctx: ToolContext) -> None:
    """Register the six object-read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_address_objects(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Address objects (IP/netmask, IP range, FQDN)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = AddressObject.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_ADDRESS_OBJECT,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_address_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Address groups (static and dynamic)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = AddressGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_ADDRESS_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_service_objects(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """TCP/UDP service objects (port and protocol)."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = ServiceObject.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_SERVICE_OBJECT,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_service_groups(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Service groups containing multiple service objects."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = ServiceGroup.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_SERVICE_GROUP,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_application_filters(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Application filters used in security policy."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = ApplicationFilter.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_APPLICATION_FILTER,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_tags(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Tags used to label rules and objects."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        items = Tag.refreshall(client)
        return apply_shape(
            panos_object_dicts(items), shape=SHAPE_TAG,
            verbose=verbose, fields=fields, pagination=pagination, pattern=pattern,
        )


__all__ = ["register_objects_tools"]
