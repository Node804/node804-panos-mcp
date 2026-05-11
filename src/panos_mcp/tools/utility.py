"""Utility tools.

- ``get_config_xpath`` (Mode.READ) — flexible read of any config subtree.
- ``run_op_command`` (Mode.ADMIN) — execute an arbitrary PAN-OS operational
  command. Last-resort escape hatch; prefer a typed tool when one exists.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp_toolkit import FieldsList, Mode, VerboseFlag
from panos.errors import PanDeviceError
from pydantic import Field

from ..responses.schemas import SHAPE_CONFIG_XPATH
from ..responses.shapers import shape_single
from ._common import ToolContext, op_to_dict, run_blocking, wrap_panos_error

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


XmlOpCommand = Annotated[
    str,
    Field(
        min_length=1,
        max_length=4096,
        pattern=r"^\s*<",
        description=(
            "PAN-OS operational XML command, e.g. '<show><system><info></info>"
            "</system></show>' or '<show><session><id>123</id></session></show>'. "
            "Sent directly to the firewall — impact depends on the command."
        ),
    ),
]


def register_utility_tools(ctx: ToolContext) -> None:
    """Register the utility tools."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_config_xpath(
        xpath: XPathParam,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Retrieve a specific config subtree by XPath.

        Use as an escape hatch when no dedicated tool covers the field
        you need. Default response strips PAN-OS internal flags
        (``@_uuid``, ``@_dirtyId``, etc.); set ``verbose=true`` to keep them.

        For large subtrees, prefer a more specific xpath — pulling the whole
        ``/config`` tree can return tens of thousands of tokens.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        cmd = (
            f"<show><config><running><xpath>{xpath}</xpath></running></config></show>"
        )
        result = op_to_dict(client, cmd)
        return shape_single(result, shape=SHAPE_CONFIG_XPATH, verbose=verbose, fields=fields)

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def run_op_command(
        command: XmlOpCommand,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Execute an arbitrary PAN-OS operational command.

        Last-resort escape hatch — prefer a typed tool (``get_firewall_info``,
        ``get_active_sessions``, etc.) when one exists. The result of every
        invocation is captured in the audit log; sanitization truncates
        commands and responses larger than 2 KB to keep audit lines bounded.

        Impact depends on the command. ``<show>`` commands are read-only,
        ``<request>`` commands can trigger upgrades/restarts/etc, ``<clear>``
        commands modify runtime state.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        try:
            response = await run_blocking(client.op, command)
        except PanDeviceError as e:
            return wrap_panos_error(e, "run_op_command", command[:80])
        # Convert ElementTree response (or pass through dict from tests).
        if isinstance(response, dict):
            return {"success": True, "result": response}
        # The client.op() return is an Element; reuse the converter.
        from ._common import element_to_dict
        result = element_to_dict(response)
        return {"success": True, "result": result}


__all__ = ["register_utility_tools"]
