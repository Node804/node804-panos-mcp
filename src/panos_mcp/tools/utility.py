"""Utility tools.

- ``get_config_xpath`` (Mode.READ) — flexible read of any config subtree.
- ``run_show_command`` (Mode.READ) — execute a read-only ``<show>`` op
  command.  Always registered.
- ``run_op_command`` (Mode.ADMIN) — execute an arbitrary PAN-OS
  operational command.  **Default-off** escape hatch; only registers when
  ``PANOS_ENABLE_RAW_OPS=true`` is set.  Even then, a denylist blocks
  reboot / software install / debug / credential mutation verbs.

The split exists because the original ``run_op_command`` accepted any
command at ADMIN mode, which made it possible to reboot the firewall or
trigger a factory reset through a single tool call.  Read-only ``<show>``
queries are useful and low-risk, so they live in their own always-on tool;
the dangerous superset is now opt-in.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp_toolkit import FieldsList, Mode, VerboseFlag
from panos.errors import PanDeviceError
from pydantic import Field

from ..responses.schemas import SHAPE_CONFIG_XPATH
from ..responses.shapers import shape_single
from ._common import (
    ToolContext,
    emit_preflight_audit,
    op_to_dict,
    run_blocking,
    wrap_panos_error,
)
from ._guards import check_op_command, is_show_command, raw_ops_enabled

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


XmlShowCommand = Annotated[
    str,
    Field(
        min_length=1,
        max_length=4096,
        # Schema-level guard: only <show ...> commands accepted.  A second
        # runtime check (``is_show_command``) defends against whitespace or
        # comment tricks that might slip past the regex.
        pattern=r"^\s*<show\b",
        description=(
            "Read-only PAN-OS show command, e.g. "
            "'<show><system><info></info></system></show>'."
        ),
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
            "Sent directly to the firewall — impact depends on the command. "
            "Reboot, software install, debug, and credential mutation commands "
            "are rejected by an internal denylist."
        ),
    ),
]


async def _execute_op(client: Any, command: str) -> dict[str, Any]:
    """Shared body for show/op tools: run ``client.op`` and normalize the
    response shape.  Passes ``cmd_xml=False`` so the XML payload is sent
    verbatim rather than re-wrapped as a CLI string.
    """
    try:
        response = await run_blocking(client.op, command, cmd_xml=False)
    except PanDeviceError as e:
        return wrap_panos_error(e, "run_op_command", command[:80])
    if isinstance(response, dict):
        return {"success": True, "result": response}
    from ._common import element_to_dict
    return {"success": True, "result": element_to_dict(response)}


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

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def run_show_command(
        command: XmlShowCommand,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Execute a read-only PAN-OS ``<show>`` operational command.

        Use when no dedicated read tool covers the data you need. Only
        ``<show>`` commands are accepted — anything else is rejected at the
        schema layer.  Read-only by PAN-OS contract: show commands do not
        modify config or runtime state.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # Defense-in-depth: re-verify after schema validation in case a
        # crafty payload slipped past the regex.
        if not is_show_command(command):
            return {
                "success": False,
                "operation": "run_show_command",
                "name": command[:80],
                "error": "run_show_command accepts only <show ...> commands.",
            }
        return await _execute_op(client, command)

    # ── Raw op-command escape hatch (gated) ─────────────────────────────────
    # Only register when the operator has opted in.  Even when registered,
    # ``check_op_command`` rejects reboot/software-install/debug/credential
    # mutation verbs before they reach the firewall.

    if not raw_ops_enabled():
        return

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def run_op_command(
        command: XmlOpCommand,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Execute an arbitrary PAN-OS operational command.

        Last-resort escape hatch — prefer ``run_show_command`` or a typed
        tool (``get_firewall_info``, ``get_active_sessions``, etc.) when one
        exists.

        Tool is only registered when ``PANOS_ENABLE_RAW_OPS=true``. Even
        then, an internal denylist blocks ``<request><shutdown>``,
        ``<request><restart>``, ``<request><system><private-data-reset>``,
        ``<request><system><software>``, ``<debug>``, ``<set><password>``
        and similar destructive verbs.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        reason = check_op_command(command)
        if reason is not None:
            return {
                "success": False,
                "operation": "run_op_command",
                "name": command[:80],
                "error": reason,
            }
        # Pre-flight audit so an operator can reconstruct intent even if
        # the firewall hangs or the host is killed mid-call.
        emit_preflight_audit(
            ctx, tool="run_op_command", firewall=firewall,
            args={
                "command_head": command[:200] + ("…" if len(command) > 200 else ""),
                "command_len": len(command),
            },
        )
        return await _execute_op(client, command)


__all__ = ["register_utility_tools"]
