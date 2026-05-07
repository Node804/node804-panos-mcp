"""Utility tool: ``get_config_xpath`` — flexible read of any config subtree."""

from __future__ import annotations

from typing import Annotated, Any

from mcp_toolkit import FieldsList, Mode, VerboseFlag
from pydantic import Field

from ..responses.schemas import SHAPE_CONFIG_XPATH
from ..responses.shapers import shape_single
from ._common import ToolContext, op_to_dict

XPathParam = Annotated[
    str,
    Field(
        min_length=1,
        description=(
            "PAN-OS XPath into the config tree (e.g. "
            "'/config/devices/entry[@name=\"localhost.localdomain\"]/network'). "
            "Must start with '/config'."
        ),
        pattern=r"^/config(/|$)",
    ),
]


def register_utility_tools(ctx: ToolContext) -> None:
    """Register the utility read tools."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_config_xpath(
        xpath: XPathParam,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Retrieve a specific config subtree by XPath.

        Use this as an escape hatch when no dedicated tool covers the field
        you need. Default response strips PAN-OS internal flags
        (``@_uuid``, ``@_dirtyId``, etc.); set ``verbose=true`` to keep them.

        For large subtrees, prefer a more specific xpath — pulling the whole
        ``/config`` tree can return tens of thousands of tokens.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # PAN-OS op-style xpath read.
        cmd = (
            f"<show><config><running><xpath>{xpath}</xpath></running></config></show>"
        )
        result = op_to_dict(client, cmd)
        return shape_single(result, shape=SHAPE_CONFIG_XPATH, verbose=verbose, fields=fields)


__all__ = ["register_utility_tools"]
