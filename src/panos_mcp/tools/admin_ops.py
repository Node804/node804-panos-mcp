"""Admin-mode operational tools.

Five tools that take user-staged changes from the candidate config to the
running firewall (or Panorama to its managed devices), plus the raw
``set_config`` / ``delete_config`` xpath escape hatches.

All require ``Mode.ADMIN``. The audit log captures every invocation with
sanitized arguments — these are the most consequential calls in the suite
and the audit trail is the operator's only after-the-fact visibility.

Pan-os-python is synchronous; calls go through :func:`run_blocking` so the
FastMCP event loop stays responsive during the seconds-to-minutes a commit
or push takes.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp_toolkit import Mode
from panos.errors import PanDeviceError
from pydantic import Field

from ._common import (
    ToolContext,
    run_blocking,
    wrap_panos_error,
    write_success,
)
from ._schemas import PanosDescription, PanosName

XPathParam = Annotated[
    str,
    Field(
        min_length=1,
        pattern=r"^/config(/|$)",
        description=(
            "PAN-OS XPath into the config tree. Must start with '/config'. "
            "Example: \"/config/devices/entry[@name='localhost.localdomain']"
            "/vsys/entry[@name='vsys1']/address\"."
        ),
    ),
]

XmlElement = Annotated[
    str,
    Field(
        min_length=1,
        max_length=65536,
        description=(
            "XML element to set at the xpath location. Must start with '<'. "
            "Example: '<entry name=\"web-srv\"><ip-netmask>10.0.0.1/32</ip-netmask></entry>'."
        ),
        pattern=r"^\s*<",
    ),
]


def _commit_result(raw: Any, name: str, operation: str) -> dict[str, Any]:
    """Normalize a pan-os-python commit response to our shape.

    pan-os-python returns either a dict (when sync=True) or a job-id string
    (when sync=False). We pass sync=False so the tool returns quickly and
    the AI can poll via ``panorama_get_commit_status``.
    """
    if isinstance(raw, dict):
        return write_success(operation, name, **raw)
    if isinstance(raw, (str, int)):
        return write_success(operation, name, job_id=str(raw))
    return write_success(operation, name)


def register_admin_ops_tools(ctx: ToolContext) -> None:
    """Register the five admin-mode operational tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def commit(
        description: PanosDescription | None = None,
        partial_admin: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Commit staged candidate config to the running firewall.

        Affects live traffic. Returns a job ID — use ``panorama_get_commit_status``
        to track completion (the 'show jobs all' command works on firewalls too).

        ``partial_admin`` limits the commit to changes made by that admin
        user (PAN-OS partial-commit feature).
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        commit_kwargs: dict[str, Any] = {"sync": False, "exception": False}
        if description:
            commit_kwargs["description"] = description
        if partial_admin:
            commit_kwargs["admins"] = [partial_admin]
        try:
            raw = await run_blocking(client.commit, **commit_kwargs)
        except PanDeviceError as e:
            return wrap_panos_error(e, "commit", "candidate")
        return _commit_result(raw, "candidate", "commit")

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def panorama_commit(
        description: PanosDescription | None = None,
        partial_admin: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Commit pending changes on Panorama (does NOT push to managed devices).

        Run this before ``panorama_push_to_devices`` — Panorama commits its
        own candidate config first, then pushes the committed config out to
        managed firewalls.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        commit_kwargs: dict[str, Any] = {"sync": False, "exception": False}
        if description:
            commit_kwargs["description"] = description
        if partial_admin:
            commit_kwargs["admins"] = [partial_admin]
        try:
            raw = await run_blocking(client.commit, **commit_kwargs)
        except PanDeviceError as e:
            return wrap_panos_error(e, "panorama_commit", "candidate")
        return _commit_result(raw, "candidate", "panorama_commit")

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def panorama_push_to_devices(
        device_group: PanosName,
        description: PanosDescription | None = None,
        include_template: bool = False,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Push device-group config from Panorama to managed firewalls.

        Affects live traffic on every firewall in the device group. Returns
        a job ID — track with ``panorama_get_push_status``.

        ``include_template`` (default False) also pushes the associated
        template stack. Use only when template variables have changed
        alongside the policy.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # pan-os-python: Panorama.commit_all(sync=True/False, sync_all=True/False,
        #   exception=False, devicegroup="...", description="...", include_template=bool)
        kwargs: dict[str, Any] = {
            "sync": False,
            "sync_all": False,
            "exception": False,
            "devicegroup": device_group,
            "include_template": include_template,
        }
        if description:
            kwargs["description"] = description
        try:
            raw = await run_blocking(client.commit_all, **kwargs)
        except PanDeviceError as e:
            return wrap_panos_error(e, "panorama_push", device_group)
        return _commit_result(raw, device_group, "panorama_push")

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def set_config(
        xpath: XPathParam,
        element: XmlElement,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Set config at an arbitrary XPath. Staged in candidate config.

        Escape hatch for fields not covered by a dedicated tool. The caller
        is responsible for building well-formed XML and a valid xpath. PAN-OS
        validates server-side; invalid xpaths or elements are surfaced as
        PanDeviceError responses.

        Prefer a typed tool (add_security_rule, add_address_object, etc.)
        when one exists — this tool bypasses the response-shape and
        validation conventions used everywhere else.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        try:
            await run_blocking(client.xapi.set, xpath, element)
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_config", xpath)
        return write_success("set_config", xpath)

    @ctx.gate.tool(ctx.mcp, required=Mode.ADMIN)
    async def delete_config(
        xpath: XPathParam,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete config at an arbitrary XPath. Staged in candidate config.

        Use with care — deleting the wrong subtree (e.g. an entire vsys or
        rulebase) removes everything beneath it. Prefer a typed
        delete_X tool when one exists.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        try:
            await run_blocking(client.xapi.delete, xpath)
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete_config", xpath)
        return write_success("delete_config", xpath)


__all__ = ["register_admin_ops_tools"]
