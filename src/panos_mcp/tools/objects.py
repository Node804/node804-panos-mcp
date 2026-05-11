"""Object read + CRUD tools.

Phase 3 reads (Mode.READ): get_address_objects, get_address_groups,
get_service_objects, get_service_groups, get_application_filters, get_tags.

Phase 4 CRUD (Mode.STANDARD): add/delete for address objects, address
groups, service objects, service groups, and tags.

Writes go to the candidate config — call ``commit`` (admin mode) to push
them to the running firewall.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.errors import PanDeviceError
from panos.objects import (
    AddressGroup,
    AddressObject,
    ApplicationFilter,
    ServiceGroup,
    ServiceObject,
    Tag,
)
from pydantic import Field

from ..responses.schemas import (
    SHAPE_ADDRESS_GROUP,
    SHAPE_ADDRESS_OBJECT,
    SHAPE_APPLICATION_FILTER,
    SHAPE_SERVICE_GROUP,
    SHAPE_SERVICE_OBJECT,
    SHAPE_TAG,
)
from ..responses.shapers import apply_shape
from ._common import (
    ToolContext,
    panos_object_dicts,
)
from ._common import (
    wrap_panos_error as _wrap_panos_error,
)
from ._common import (
    write_success as _success,
)
from ._schemas import PanosDescription, PanosName, PanosTagName

# Tag color values are an enumerated set in PAN-OS (color1..color16).
_TAG_COLORS = tuple(f"color{i}" for i in range(1, 17))
TagColor = Literal[
    "color1", "color2", "color3", "color4",
    "color5", "color6", "color7", "color8",
    "color9", "color10", "color11", "color12",
    "color13", "color14", "color15", "color16",
]


def register_objects_tools(ctx: ToolContext) -> None:
    """Register the 6 read + 10 CRUD object tools against ``ctx.mcp``."""

    # ── Reads (Mode.READ) ───────────────────────────────────────────────────

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
            panos_object_dicts(items),
            shape=SHAPE_ADDRESS_OBJECT,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
            panos_object_dicts(items),
            shape=SHAPE_ADDRESS_GROUP,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
            panos_object_dicts(items),
            shape=SHAPE_SERVICE_OBJECT,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
            panos_object_dicts(items),
            shape=SHAPE_SERVICE_GROUP,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
            panos_object_dicts(items),
            shape=SHAPE_APPLICATION_FILTER,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
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
            panos_object_dicts(items),
            shape=SHAPE_TAG,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    # ── Address objects: CRUD (Mode.STANDARD) ───────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def add_address_object(
        name: PanosName,
        value: Annotated[
            str,
            Field(
                min_length=1,
                description=(
                    "Address value. Format depends on type: "
                    "ip-netmask='10.0.0.0/24', ip-range='10.0.0.1-10.0.0.10', "
                    "fqdn='example.com'."
                ),
            ),
        ],
        type: Literal["ip-netmask", "ip-range", "fqdn"] = "ip-netmask",
        description: PanosDescription | None = None,
        tag: list[PanosTagName] | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create an address object on the firewall.

        Staged in candidate config — call ``commit`` (admin mode) to activate.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = AddressObject(
            name=name, value=value, type=type, description=description, tag=tag
        )
        client.add(obj)
        try:
            obj.create()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "create", name)
        return _success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def delete_address_object(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete an address object from the firewall.

        Staged in candidate config — call ``commit`` (admin mode) to activate.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = AddressObject(name=name)
        client.add(obj)
        try:
            obj.delete()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "delete", name)
        return _success("deleted", name)

    # ── Address groups: CRUD ─────────────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def add_address_group(
        name: PanosName,
        members: Annotated[
            list[PanosName],
            Field(min_length=1, description="Names of address objects/groups to include."),
        ],
        description: PanosDescription | None = None,
        tag: list[PanosTagName] | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a static address group from existing address objects.

        Staged in candidate config — call ``commit`` to activate.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = AddressGroup(
            name=name, static_value=members, description=description, tag=tag
        )
        client.add(obj)
        try:
            obj.create()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "create", name)
        return _success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def delete_address_group(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete an address group. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = AddressGroup(name=name)
        client.add(obj)
        try:
            obj.delete()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "delete", name)
        return _success("deleted", name)

    # ── Service objects: CRUD ───────────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def add_service_object(
        name: PanosName,
        protocol: Literal["tcp", "udp"],
        destination_port: Annotated[
            str,
            Field(
                min_length=1,
                pattern=r"^\d+(-\d+)?$",
                description=(
                    "Destination port or range, e.g. '443' or '8000-8080'."
                ),
            ),
        ],
        source_port: Annotated[
            str | None,
            Field(
                default=None,
                pattern=r"^\d+(-\d+)?$",
                description="Optional source port or range.",
            ),
        ] = None,
        description: PanosDescription | None = None,
        tag: list[PanosTagName] | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a TCP/UDP service object. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = ServiceObject(
            name=name,
            protocol=protocol,
            destination_port=destination_port,
            source_port=source_port,
            description=description,
            tag=tag,
        )
        client.add(obj)
        try:
            obj.create()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "create", name)
        return _success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def delete_service_object(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a service object. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = ServiceObject(name=name)
        client.add(obj)
        try:
            obj.delete()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "delete", name)
        return _success("deleted", name)

    # ── Service groups: CRUD ────────────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def add_service_group(
        name: PanosName,
        members: Annotated[
            list[PanosName],
            Field(min_length=1, description="Names of service objects/groups to include."),
        ],
        tag: list[PanosTagName] | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a service group. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = ServiceGroup(name=name, value=members, tag=tag)
        client.add(obj)
        try:
            obj.create()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "create", name)
        return _success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def delete_service_group(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a service group. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = ServiceGroup(name=name)
        client.add(obj)
        try:
            obj.delete()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "delete", name)
        return _success("deleted", name)

    # ── Tags: CRUD ──────────────────────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def add_tag(
        name: PanosTagName,
        color: TagColor | None = None,
        comments: PanosDescription | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create a tag. Color is one of color1..color16 (PAN-OS palette).

        Staged in candidate config — call ``commit`` to activate.
        """
        # _TAG_COLORS is exported for documentation/test introspection.
        _ = _TAG_COLORS
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = Tag(name=name, color=color, comments=comments)
        client.add(obj)
        try:
            obj.create()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "create", name)
        return _success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.STANDARD)
    async def delete_tag(
        name: PanosTagName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a tag. Staged in candidate config."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        obj = Tag(name=name)
        client.add(obj)
        try:
            obj.delete()
        except PanDeviceError as e:
            return _wrap_panos_error(e, "delete", name)
        return _success("deleted", name)


__all__ = ["register_objects_tools"]
