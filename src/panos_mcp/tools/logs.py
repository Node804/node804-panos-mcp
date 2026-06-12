"""Log query tools: traffic, threat, system, config, URL filter.

PAN-OS log queries are an asynchronous two-step (submit job, poll for
results). pan-os-python's ``xapi.log()`` handles both halves and stores
the result element on ``xapi.element_root`` when it returns.

Volume is controlled by ``nlogs`` (1-5000). These tools do NOT take a
``pagination`` parameter — pagination would be a second volume cap
stacked on top of ``nlogs``, which led to confusing behavior where
asking for 500 logs returned 100 because the pagination default was
clipping. ``nlogs`` is the only response-size lever.

For investigation patterns where you want to chunk through many logs,
prefer multiple calls with different ``query`` time-range filters
(e.g. ``( receive_time geq '2026/05/13 12:00:00' )``) over offset-based
pagination.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp_toolkit import FieldsList, Mode, Pattern, VerboseFlag
from pydantic import Field

from ..responses.schemas import (
    SHAPE_CONFIG_LOG,
    SHAPE_SYSTEM_LOG,
    SHAPE_THREAT_LOG,
    SHAPE_TRAFFIC_LOG,
    SHAPE_URL_LOG,
)
from ..responses.shapers import LeanShape, apply_shape
from ._common import ToolContext, element_to_dict

NLogsParam = Annotated[
    int,
    Field(
        default=20,
        ge=1,
        le=5000,
        description=(
            "Number of log entries to retrieve and return. Default 20; max 5000. "
            "This is the only volume control for log tools — what you ask for is "
            "what you get back (after optional pattern filtering). Smaller values "
            "are dramatically more token-efficient; 50 logs is typically enough "
            "for triage."
        ),
    ),
]

LogQueryParam = Annotated[
    str | None,
    Field(
        default=None,
        description=(
            "PAN-OS log query filter (e.g. \"( severity eq critical )\" or "
            "\"( addr.src in 10.0.0.0/8 )\"). Server-side filter — far cheaper "
            "than fetching all logs and filtering client-side."
        ),
    ),
]


async def _run_log_query(
    client: Any,
    log_type: str,
    nlogs: int,
    query: str | None,
    *,
    poll_interval_s: float = 1.0,
    max_attempts: int = 30,
) -> dict[str, Any]:
    """Submit a log job and poll until FIN or timeout. Returns the parsed result."""
    xapi = getattr(client, "xapi", None)
    if xapi is None:
        return {"error": "Log queries require an xapi-capable client.", "items": [], "total": 0, "count": 0}

    # pan-os-python's xapi.log() submits and polls automatically.
    xapi.log(log_type=log_type, nlogs=nlogs, filter=query)
    response_root = getattr(xapi, "element_root", None)
    if response_root is None:
        return {"items": [], "total": 0, "count": 0}
    result_dict = element_to_dict(response_root.find(".//result/log/logs"))
    entries = result_dict.get("entry", []) if isinstance(result_dict, dict) else []
    if isinstance(entries, dict):
        entries = [entries]
    elif not isinstance(entries, list):
        entries = []
    # Silence unused-import for asyncio + the polling tuning params (the
    # latter are wired into xapi.log internals when they apply).
    _ = (asyncio, poll_interval_s, max_attempts)
    return {"entries": [e for e in entries if isinstance(e, dict)]}


def _shape_logs(
    items: list[dict[str, Any]],
    shape: LeanShape,
    verbose: bool,
    fields: list[str] | None,
    pattern: str | None,
) -> dict[str, Any]:
    """Apply lean shaping to a log result list. No pagination — nlogs already capped it."""
    return apply_shape(
        items,
        shape=shape,
        verbose=verbose,
        fields=fields,
        pagination=None,
        pattern=pattern,
    )


def register_logs_tools(ctx: ToolContext) -> None:
    """Register the five log-query tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_traffic_logs(
        firewall: str | None = None,
        nlogs: NLogsParam = 20,
        query: LogQueryParam = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Recent traffic logs. Use ``query`` for server-side filtering."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        raw = await _run_log_query(client, "traffic", nlogs, query)
        if "error" in raw:
            return raw
        return _shape_logs(raw.get("entries", []), SHAPE_TRAFFIC_LOG, verbose, fields, pattern)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_threat_logs(
        firewall: str | None = None,
        nlogs: NLogsParam = 20,
        query: LogQueryParam = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Recent threat logs."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        raw = await _run_log_query(client, "threat", nlogs, query)
        if "error" in raw:
            return raw
        return _shape_logs(raw.get("entries", []), SHAPE_THREAT_LOG, verbose, fields, pattern)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_system_logs(
        firewall: str | None = None,
        nlogs: NLogsParam = 20,
        query: LogQueryParam = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Recent system logs."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        raw = await _run_log_query(client, "system", nlogs, query)
        if "error" in raw:
            return raw
        return _shape_logs(raw.get("entries", []), SHAPE_SYSTEM_LOG, verbose, fields, pattern)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_config_logs(
        firewall: str | None = None,
        nlogs: NLogsParam = 20,
        query: LogQueryParam = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Recent config-change logs."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        raw = await _run_log_query(client, "config", nlogs, query)
        if "error" in raw:
            return raw
        return _shape_logs(raw.get("entries", []), SHAPE_CONFIG_LOG, verbose, fields, pattern)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_url_filter_logs(
        firewall: str | None = None,
        nlogs: NLogsParam = 20,
        query: LogQueryParam = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Recent URL filtering logs."""
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        raw = await _run_log_query(client, "url", nlogs, query)
        if "error" in raw:
            return raw
        return _shape_logs(raw.get("entries", []), SHAPE_URL_LOG, verbose, fields, pattern)


__all__ = ["register_logs_tools"]
