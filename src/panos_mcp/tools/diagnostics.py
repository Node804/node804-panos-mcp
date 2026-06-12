"""Live-troubleshooting read tools (Mode.READ).

These wrap PAN-OS *operational* commands that answer the questions a network
engineer asks while something is actively broken:

- ``test_security_policy_match`` / ``test_nat_policy_match`` — "is this flow
  allowed, and by which rule?" / "how is it translated?". These are the
  read-only ``<test>`` ops; PAN-OS evaluates them against the *running*
  policy without touching state.
- ``test_routing_fib_lookup`` — "which interface / next-hop does this
  destination egress?".
- ``get_sessions`` — filtered live session table (``show session all
  filter ...``) with NAT-translation fields in the lean view.
- ``get_session_detail`` — full per-session record (``show session id N``).

All are per-firewall operational commands. When the resolved target is a
Panorama appliance they return a clear error pointing the caller at the
``firewall`` parameter — Panorama has no session table or live policy engine
of its own.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any
from xml.sax.saxutils import escape as _xml_escape

from node804_mcp_toolkit import FieldsList, Mode, Pagination, VerboseFlag
from panos.errors import PanDeviceError
from panos.panorama import Panorama
from pydantic import Field

from ..responses.schemas import (
    SHAPE_POLICY_MATCH,
    SHAPE_SESSION,
    SHAPE_SESSION_DETAIL,
)
from ..responses.shapers import apply_shape, shape_single
from ._common import ToolContext, op_to_dict, wrap_panos_error

# ── Input types ─────────────────────────────────────────────────────────────

Protocol = Annotated[
    int,
    Field(
        ge=1,
        le=255,
        description="IP protocol number (6=TCP, 17=UDP, 1=ICMP). PAN-OS requires this.",
    ),
]

Port = Annotated[
    int,
    Field(ge=0, le=65535, description="TCP/UDP port number (0-65535)."),
]

AppName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=63,
        description="Optional application name to test with (e.g. 'ssl', 'web-browsing').",
    ),
]

ZoneName = Annotated[
    str,
    Field(min_length=1, max_length=63, description="Optional source/destination zone name."),
]


def _ip_error(label: str, value: str, operation: str) -> dict[str, Any] | None:
    """Return an error dict if ``value`` isn't a bare IP address, else None."""
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return {
            "success": False,
            "operation": operation,
            "error": (
                f"{label} must be a single IP address (not a CIDR, range, or "
                f"object name); got {value!r}."
            ),
        }
    return None


def _el(tag: str, value: Any) -> str:
    """Render one XML element with an escaped text value."""
    return f"<{tag}>{_xml_escape(str(value))}</{tag}>"


def _panorama_guard(client: Any, operation: str) -> dict[str, Any] | None:
    """Return an error dict when ``client`` is a Panorama (per-firewall op)."""
    if isinstance(client, Panorama):
        return {
            "success": False,
            "operation": operation,
            "error": (
                f"'{operation}' is a per-firewall operational command and cannot "
                "run against Panorama directly. Specify a managed firewall with "
                "the 'firewall' parameter (use list_firewalls to see targets)."
            ),
        }
    return None


def register_diagnostics_tools(ctx: ToolContext) -> None:
    """Register the live-troubleshooting read tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def test_security_policy_match(
        source: str,
        destination: str,
        protocol: Protocol = 6,
        destination_port: Port = 443,
        application: AppName | None = None,
        source_user: str | None = None,
        from_zone: ZoneName | None = None,
        to_zone: ZoneName | None = None,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Which security rule a flow matches — the live ``test security-policy-match``.

        Read-only: PAN-OS evaluates the flow against the *running* policy and
        returns the matching rule(s) without changing any state. This is the
        fastest answer to "is traffic from X to Y allowed, and by which rule?".

        ``protocol`` and ``destination_port`` are required by PAN-OS (integers
        only — no 'any'). ``application``, ``source_user``, and the zones are
        optional refinements. Returns the matched rule under ``matched`` with
        the query echoed back.
        """
        op = "test_security_policy_match"
        for label, value in (("source", source), ("destination", destination)):
            err = _ip_error(label, value, op)
            if err is not None:
                return err
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = _panorama_guard(client, op)
        if guard is not None:
            return guard

        parts = [_el("source", source), _el("destination", destination)]
        parts.append(_el("protocol", protocol))
        parts.append(_el("destination-port", destination_port))
        if application:
            parts.append(_el("application", application))
        if source_user:
            parts.append(_el("source-user", source_user))
        if from_zone:
            parts.append(_el("from", from_zone))
        if to_zone:
            parts.append(_el("to", to_zone))
        cmd = f"<test><security-policy-match>{''.join(parts)}</security-policy-match></test>"

        try:
            result = op_to_dict(client, cmd)
        except PanDeviceError as e:
            return wrap_panos_error(e, op, f"{source}->{destination}")
        query = {
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "destination_port": destination_port,
            "application": application,
            "source_user": source_user,
            "from_zone": from_zone,
            "to_zone": to_zone,
        }
        matched = shape_single(result, shape=SHAPE_POLICY_MATCH, verbose=verbose, fields=fields)
        return {"query": {k: v for k, v in query.items() if v is not None}, "matched": matched}

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def test_nat_policy_match(
        source: str,
        destination: str,
        protocol: Protocol = 6,
        destination_port: Port = 443,
        from_zone: ZoneName | None = None,
        to_zone: ZoneName | None = None,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Which NAT rule a flow matches and how it's translated — ``test nat-policy-match``.

        Read-only. Returns the matching NAT rule plus the translated
        source/destination/port so you can confirm a flow is (or isn't) being
        translated the way you expect.
        """
        op = "test_nat_policy_match"
        for label, value in (("source", source), ("destination", destination)):
            err = _ip_error(label, value, op)
            if err is not None:
                return err
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = _panorama_guard(client, op)
        if guard is not None:
            return guard

        parts = [_el("source", source), _el("destination", destination)]
        parts.append(_el("protocol", protocol))
        parts.append(_el("destination-port", destination_port))
        if from_zone:
            parts.append(_el("from", from_zone))
        if to_zone:
            parts.append(_el("to", to_zone))
        cmd = f"<test><nat-policy-match>{''.join(parts)}</nat-policy-match></test>"

        try:
            result = op_to_dict(client, cmd)
        except PanDeviceError as e:
            return wrap_panos_error(e, op, f"{source}->{destination}")
        query = {
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "destination_port": destination_port,
            "from_zone": from_zone,
            "to_zone": to_zone,
        }
        matched = shape_single(result, shape=SHAPE_POLICY_MATCH, verbose=verbose, fields=fields)
        return {"query": {k: v for k, v in query.items() if v is not None}, "matched": matched}

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def test_routing_fib_lookup(
        ip: str,
        virtual_router: str = "default",
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Egress interface / next-hop for a destination — ``test routing fib-lookup``.

        Read-only FIB lookup against the named virtual router. Answers "where
        does traffic to this destination go?" without touching state.
        """
        op = "test_routing_fib_lookup"
        err = _ip_error("ip", ip, op)
        if err is not None:
            return err
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = _panorama_guard(client, op)
        if guard is not None:
            return guard

        cmd = (
            "<test><routing><fib-lookup>"
            f"{_el('virtual-router', virtual_router)}{_el('ip', ip)}"
            "</fib-lookup></routing></test>"
        )
        try:
            result = op_to_dict(client, cmd)
        except PanDeviceError as e:
            return wrap_panos_error(e, op, ip)
        query = {"ip": ip, "virtual_router": virtual_router}
        result_shaped = shape_single(
            result, shape=SHAPE_POLICY_MATCH, verbose=verbose, fields=fields
        )
        return {"query": query, "result": result_shaped}

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_sessions(
        source: str | None = None,
        destination: str | None = None,
        destination_port: Port | None = None,
        protocol: Protocol | None = None,
        application: AppName | None = None,
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
    ) -> dict[str, Any]:
        """Live session table, filtered — ``show session all filter ...``.

        Pass any combination of ``source`` / ``destination`` (single IPs),
        ``destination_port``, ``protocol``, ``application`` to narrow the
        result. With no filter the firewall returns its full session list
        (bounded by pagination). The lean view includes the NAT-translation
        fields (``xsource``, ``xdst``, ``xdport``, ``nat``) so you can see
        both the original and translated tuple in one place.
        """
        op = "get_sessions"
        for label, value in (("source", source), ("destination", destination)):
            if value is not None:
                err = _ip_error(label, value, op)
                if err is not None:
                    return err
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = _panorama_guard(client, op)
        if guard is not None:
            return guard

        filters: list[str] = []
        if source:
            filters.append(_el("source", source))
        if destination:
            filters.append(_el("destination", destination))
        if destination_port is not None:
            filters.append(_el("destination-port", destination_port))
        if protocol is not None:
            filters.append(_el("protocol", protocol))
        if application:
            filters.append(_el("application", application))
        filter_xml = f"<filter>{''.join(filters)}</filter>" if filters else ""
        cmd = f"<show><session><all>{filter_xml}</all></session></show>"

        try:
            result = op_to_dict(client, cmd)
        except PanDeviceError as e:
            return wrap_panos_error(e, op, "session-table")
        entries = result.get("entry", []) if isinstance(result, dict) else []
        if isinstance(entries, dict):
            entries = [entries]
        elif not isinstance(entries, list):
            entries = []
        items = [e for e in entries if isinstance(e, dict)]
        return apply_shape(
            items, shape=SHAPE_SESSION, verbose=verbose, fields=fields, pagination=pagination
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_session_detail(
        session_id: Annotated[int, Field(ge=1, description="Session ID from get_sessions.")],
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
    ) -> dict[str, Any]:
        """Full detail for one session — ``show session id <N>``.

        Use the ``id`` from ``get_sessions`` to pull the complete record:
        timing, byte/packet counters, both halves of the flow, NAT
        translation, and the matched security/NAT rules.
        """
        op = "get_session_detail"
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = _panorama_guard(client, op)
        if guard is not None:
            return guard

        cmd = f"<show><session><id>{session_id}</id></session></show>"
        try:
            result = op_to_dict(client, cmd)
        except PanDeviceError as e:
            return wrap_panos_error(e, op, str(session_id))
        return shape_single(result, shape=SHAPE_SESSION_DETAIL, verbose=verbose, fields=fields)


__all__ = ["register_diagnostics_tools"]
