"""Shared helpers used by every read tool.

The common pattern is:

1. Resolve the pan-os-python client for the requested target (or return an error dict).
2. Run a pan-os-python op command or config read, getting either a dict
   (op) or a list of objects (config).
3. Convert XML/objects to plain dicts.
4. Apply :func:`apply_shape` (list responses) or :func:`shape_single` (one record).

These helpers package the boilerplate so tool modules stay focused on the
PAN-OS-specific call.

A :class:`ToolContext` dataclass bundles the cross-cutting state (FastMCP
instance, RBAC gate, TLS config) that every register function needs. The
server constructs one and passes it to every ``register_*_tools(ctx)`` call.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC
from typing import Annotated, Any
from xml.etree.ElementTree import Element
from xml.sax.saxutils import escape as _xml_escape

from mcp.server.fastmcp import FastMCP
from node804_mcp_toolkit import ModeGate, TlsConfig
from pydantic import Field

from .._redact import redact_exception
from ..client import ResolveError, get_client


@dataclass(frozen=True)
class ToolContext:
    """Cross-cutting state passed to every ``register_*_tools`` function.

    The server builds one of these at startup; tool modules use it to
    decorate handlers (``ctx.gate.tool(ctx.mcp, ...)``) and resolve clients
    (``ctx.resolve(firewall)``).

    ``audit_sink`` is optional and defaults to ``None`` to keep the legacy
    constructor signature compatible.  When supplied (server.py wires the
    same sink that drives ``ModeGate``), high-impact tools call
    :func:`emit_preflight_audit` *before* contacting the firewall so an
    operator has evidence the call was attempted even if the process is
    killed mid-flight.  This is defense-in-depth: the toolkit decorator
    still emits its own success/failure record after the call.
    """

    mcp: FastMCP
    gate: ModeGate
    tls: TlsConfig
    audit_sink: Any = None

    def resolve(self, firewall: str | None) -> Any:
        """Resolve a target to a pan-os-python client or return an error dict.

        Returns either the live client (Firewall/Panorama) or a dict like
        ``{"error": "..."}``. Tools check ``isinstance(result, dict)`` to
        short-circuit::

            client = ctx.resolve(firewall)
            if isinstance(client, dict):
                return client
            # ... use client ...
        """
        result = get_client(firewall, tls=self.tls)
        if isinstance(result, ResolveError):
            return {"error": result.message}
        return result


def emit_preflight_audit(
    ctx: ToolContext,
    *,
    tool: str,
    firewall: str | None,
    args: dict[str, Any],
) -> None:
    """Emit a pre-flight audit record for a high-impact tool.

    Called *before* the network operation kicks off.  The toolkit's gate
    decorator emits its own post-call record with success/duration, but
    that record never fires if the process is killed or pan-os-python
    hangs indefinitely.  This pre-flight record guarantees forensic
    visibility into *attempted* state-changing calls regardless.

    Records are tagged with ``extra={"phase": "preflight"}`` so a log
    reader can distinguish them from the regular post-call audit.

    Arguments must already be sanitized — never pass raw API keys or
    full XML payloads.  Truncate big payloads at the call site.
    """
    sink = ctx.audit_sink
    if sink is None or not getattr(sink, "enabled", False):
        return
    # Best-effort: import here so a missing/renamed AuditEvent type in a
    # future toolkit release doesn't break the import chain for everyone.
    try:
        import uuid
        from datetime import datetime

        from node804_mcp_toolkit import AuditEvent

        event = AuditEvent(
            ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
            request_id=str(uuid.uuid4()),
            tool=tool,
            # AuditCategory is a Literal alias, not an Enum, so we pass the
            # raw string value.
            category="ADMIN",
            mode=str(getattr(ctx.gate, "mode", "unknown")),
            args=args,
            success=True,
            duration_ms=0,
            error=None,
            extra={"phase": "preflight", "firewall": firewall or ""},
        )
        sink.write(event)
    except Exception:  # pragma: no cover — never let audit failure break a call
        pass


def element_to_dict(element: Element | None) -> dict[str, Any]:
    """Convert an ElementTree.Element to a plain dict.

    Conversion rules:
      - element attributes become ``@_<name>`` keys
      - element text (when present alongside children) becomes ``#text``
      - leaf elements with text become the text string
      - repeated child names collapse into a list
      - empty elements become None

    The PAN-OS XML API uses a small set of conventions consistently so this
    lightweight converter handles all responses we care about.
    """
    if element is None:
        return {}
    converted = _convert(element)
    if isinstance(converted, dict):
        return converted
    return {"#text": converted} if converted is not None else {}


def _convert(element: Element) -> Any:
    children = list(element)
    has_attrs = bool(element.attrib)
    text = (element.text or "").strip()

    if not children and not has_attrs:
        return text or None

    out: dict[str, Any] = {}
    for k, v in element.attrib.items():
        out[f"@_{k}"] = v
    if text:
        out["#text"] = text

    for child in children:
        value = _convert(child)
        existing = out.get(child.tag)
        if existing is None:
            out[child.tag] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            out[child.tag] = [existing, value]
    return out


def build_running_config_xpath_cmd(xpath: str) -> str:
    """Build a ``<show><config><running>`` op command for an XPath.

    The xpath is XML-escaped (``&``, ``<``, ``>``) before interpolation so
    that no value — even a caller-supplied one — can break out of the
    ``<xpath>`` element and inject sibling op-command XML. Quotes are left
    intact because PAN-OS xpath predicates legitimately use them
    (``entry[@name="x"]``); escaping ``<``/``>`` is sufficient to prevent
    structural breakout. Callers passing module constants get the same
    treatment at zero cost, so this hole can't be reintroduced by a refactor.
    """
    return f"<show><config><running><xpath>{_xml_escape(xpath)}</xpath></running></config></show>"


def op_to_dict(client: Any, cmd: str, *, cmd_xml: bool = False) -> dict[str, Any]:
    """Run a PAN-OS op command and return its ``<result>`` content as a dict.

    Wraps ``client.op(cmd)`` and unwraps the standard
    ``<response status="success"><result>...</result></response>`` envelope.
    Returns ``{}`` when the response has no result element.

    ``cmd_xml`` defaults to ``False`` — ``cmd`` is sent verbatim as an XML
    payload. Pass ``cmd_xml=True`` for a CLI-style command string (e.g.
    ``"show config list changes"``) and let pan-os-python build the XML; use
    this for config-management verbs whose XML structure is awkward to author
    by hand. Only pass ``cmd_xml=True`` with trusted/constant command strings.

    Tests can mock ``client.op`` to return a dict directly; this function
    handles both real Element responses and pre-converted dicts.
    """
    response = client.op(cmd, cmd_xml=cmd_xml)
    if isinstance(response, dict):
        return response
    if isinstance(response, Element):
        result = response.find("./result")
        return element_to_dict(result)
    return {}


def config_xpath_to_dict(client: Any, xpath: str) -> dict[str, Any]:
    """Read a running-config subtree by XPath and return ``<result>`` as a dict.

    Uses the dedicated config xpath API (``xapi.show(xpath=...)``) rather than
    wrapping the xpath in a ``<show><config><running><xpath>`` **op** command.
    The op form is CLI-tokenized by PAN-OS, so a predicate value containing a
    space — e.g. ``entry[@name='Lafayette Plant']`` — is truncated at the space
    (``entry[@name='Lafayette``) and the device returns "No such node". The
    xpath API passes the value as a structured parameter (the same path
    ``refreshall`` uses), so names with spaces resolve correctly.

    Mirrors :func:`op_to_dict`'s contract: returns the result subtree as a dict
    (``{}`` when empty), and lets pan-os-python raise ``PanDeviceError`` on a
    real failure. Tests can mock ``client.xapi.show`` to return a dict directly.
    """
    response = client.xapi.show(xpath=xpath)
    # pan.xapi.show returns None and stashes the parsed <response> on
    # ``element_root``; the test double returns a dict directly.
    if isinstance(response, dict):
        return response
    root = getattr(client.xapi, "element_root", None)
    if isinstance(root, Element):
        return element_to_dict(root.find("./result"))
    if isinstance(response, Element):
        return element_to_dict(response.find("./result") or response)
    return {}


def _coerce_disabled(value: Any) -> bool:
    """Normalize PAN-OS's mixed ``disabled`` representation to a real bool.

    pan-os-python's ``.about()`` returns ``disabled`` as either a Python
    ``bool``, the PAN-OS XML strings ``"yes"``/``"no"``, or ``None`` when
    the field isn't explicitly set (which PAN-OS treats as "enabled" — i.e.
    ``disabled = False``). All three are equivalent on the wire but the
    response shape leaks the difference: the lean shaper's ``drop_when_none``
    pass strips the field for ``None``, leaving enabled rules without a
    ``disabled`` key at all while disabled rules show ``disabled: true``.
    """
    if value is True or value is False:
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "1")
    return False


# Individual security-profile fields on a ``SecurityRule.about()`` dict.
# pan-os-python exposes profile attachments two ways:
#   1. ``group`` — a single profile-group name (referenced from the
#      ``profile-setting/group`` xpath); the simple case the original
#      ``has_profile`` heuristic understood.
#   2. Individual profile attachments under ``profile-setting/profiles``,
#      surfaced by ``.about()`` as discrete top-level keys (``virus``,
#      ``spyware``, etc.). Whole environments commonly use *only* this
#      pattern — no profile group — which the old check silently mis-counted
#      as "no inspection" and produced confident wrong audit findings.
# Any one of these fields being non-empty means the rule applies an L7
# inspection profile.
_INDIVIDUAL_PROFILE_FIELDS: tuple[str, ...] = (
    "virus",
    "spyware",
    "vulnerability",
    "url_filtering",
    "file_blocking",
    "data_filtering",
    "wildfire_analysis",
)


def _has_individual_profile(rule: dict[str, Any]) -> bool:
    """True when any individual L7 profile attachment is set on the rule."""
    return any(bool(rule.get(field)) for field in _INDIVIDUAL_PROFILE_FIELDS)


def rule_has_inspection(rule: dict[str, Any]) -> bool:
    """Single source of truth for "does this security rule apply inspection?".

    True when either a profile group is bound (``group``) or any individual
    L7 profile is attached. Used by :func:`enrich_security_rule_dicts` and by
    the policy-summary aggregator so the per-rule flag and the rolled-up
    "rules without inspection" count never disagree.
    """
    return bool(rule.get("group")) or _has_individual_profile(rule)


def enrich_security_rule_dicts(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize the audit-relevant fields in a list of ``.about()`` rule dicts.

    Adds two derived booleans, ``has_inspection`` and ``has_log_setting``, and
    coerces ``disabled`` to a real bool so it can't be silently stripped by
    ``drop_when_none`` for enabled rules.

      - ``has_inspection`` — true when the rule applies an L7 security
        profile, either as a profile group (``group``) or as any individual
        profile attachment (``virus``, ``spyware``, ``vulnerability``,
        ``url_filtering``, ``file_blocking``, ``data_filtering``,
        ``wildfire_analysis``). Previously named ``has_profile`` and computed
        from ``group`` / ``profile_setting`` only — but ``profile_setting``
        is never a top-level key on a pan-os-python ``.about()`` dict, so
        the old flag was effectively "is there a profile *group*?" and
        misreported every environment that uses individual profile
        attachment (a very common Panorama pattern) as having no
        inspection. See :func:`rule_has_inspection` for the canonical check.

      - ``has_log_setting`` — true when ``log_setting`` is a non-empty string.

      - ``disabled`` — always a bool. Previously the lean shape returned
        ``disabled: true`` only on the disabled rule and dropped the field
        entirely on every enabled rule (because ``.about()`` returns ``None``
        when the field isn't set, and ``drop_when_none`` strips it). That
        made it impossible for the AI to tell "enabled" from "field missing"
        — readers couldn't trust the lean response to be schema-consistent
        across the list.

    Returns the same list for chaining. Modifies dicts in place.
    """
    for r in rules:
        r["has_inspection"] = rule_has_inspection(r)
        r["has_log_setting"] = bool(r.get("log_setting"))
        r["disabled"] = _coerce_disabled(r.get("disabled"))
    return rules


# ── Attribute filter for rule listings ─────────────────────────────────────
# The toolkit's ``pattern`` parameter is bound to a single name field, which
# is the right primitive for "find this rule by name". Audits want a
# different primitive: "find rules where ``source`` contains ``X`` AND
# ``application`` includes ``any`` AND ``has_inspection`` is false". Doing that
# client-side costs tokens proportional to the rule count. ``filter_by_attrs``
# is a small server-side AND-of-substrings filter that runs *before* the
# lean projection, so the AI can filter on fields that aren't in the default
# whitelist (e.g. ``source``) without flipping ``verbose=true``.


AttrFilter = Annotated[
    dict[str, str] | None,
    Field(
        default=None,
        description=(
            "Server-side attribute filter as a JSON object: "
            "``{field: substring}``. All conditions must match (AND). Matches "
            "case-insensitively against the field's stringified value; for "
            "list fields (source, destination, application, fromzone, "
            "tozone, service) it matches when ANY element contains the "
            "substring. Booleans like ``has_inspection`` / ``has_log_setting`` "
            "/ ``disabled`` accept ``'true'`` or ``'false'``. Examples: "
            '``{"source": "10.0.0.0/24"}`` → rules whose source list '
            'contains that CIDR token; ``{"application": "any", '
            '"action": "allow"}`` → any-application allow rules; '
            '``{"has_inspection": "false"}`` → rules missing inspection. '
            "Runs before lean projection, so you can filter on verbose-only "
            "fields without setting ``verbose=true``. Note: the old key "
            "``has_profile`` was renamed to ``has_inspection`` — passing the "
            "old key returns an explicit error rather than zero rows, so an "
            "AI audit doesn't mistake a stale filter for a clean policy."
        ),
    ),
]


def _attr_value_matches(value: Any, needle: str) -> bool:
    """Case-insensitive substring match over a field's value.

    Lists and tuples match when any element contains the needle. Booleans
    and numbers are stringified (``str(True).casefold() == "true"``).
    ``None`` never matches — a missing field can't satisfy a filter.
    """
    if value is None:
        return False
    if isinstance(value, (list, tuple, set)):
        return any(_attr_value_matches(v, needle) for v in value)
    needle_cf = needle.casefold()
    if isinstance(value, bool):
        return needle_cf in str(value).casefold()
    if isinstance(value, (int, float)):
        return needle_cf in str(value)
    if isinstance(value, str):
        return needle_cf in value.casefold()
    # dict / unexpected → stringify, last resort. Keeps the filter total
    # rather than blowing up on a structured field we didn't enumerate.
    return needle_cf in str(value).casefold()


# Keys that were renamed during the unreleased window. The replacement is a
# real top-level field on the enriched rule dict; the old key is *not* — so
# silently filtering on it would match nothing and look like a valid empty
# result to an AI caller ("no rules missing inspection — clean!"), the same
# class of confidently-wrong failure that motivated the rename itself.
# Reject the old key at the entry of any tool that accepts ``attrs`` for
# security-rule listings.
_RENAMED_ATTR_KEYS: dict[str, str] = {
    "has_profile": "has_inspection",
}


def check_renamed_attr_keys(
    attrs: Mapping[str, str] | None,
) -> dict[str, Any] | None:
    """Return an error dict if ``attrs`` uses a renamed key, else ``None``.

    The output field this filter matches against was renamed in the
    unreleased window (``has_profile`` → ``has_inspection``). Silently
    returning zero rows for the old key is the worst failure mode for an
    AI-driven audit — it reads as "no findings" — so we reject the call
    with a message that tells the caller exactly which key to use.

    Returns the dict the tool should return as-is; ``None`` when ``attrs``
    is fine to proceed with.
    """
    if not attrs:
        return None
    bad = {k: _RENAMED_ATTR_KEYS[k] for k in attrs if k in _RENAMED_ATTR_KEYS}
    if not bad:
        return None
    fixes = ", ".join(f"'{old}' → '{new}'" for old, new in bad.items())
    return {
        "error": (
            f"attrs uses renamed field key(s) ({fixes}). The old key is no "
            "longer present on the rule projection, so filtering by it "
            "would silently return zero matches — rejecting the call "
            "instead so the audit isn't misled."
        ),
        "count": 0,
        "items": [],
    }


def filter_by_attrs(
    items: Iterable[Mapping[str, Any]],
    attrs: Mapping[str, str] | None,
) -> list[Mapping[str, Any]]:
    """Return items where every ``(field, needle)`` pair matches.

    ANDs all conditions; an empty/None filter is a passthrough. An item
    that's missing one of the filtered fields fails that condition (no
    implicit pass-through — silent passes would defeat the audit workflow
    that motivated this filter).
    """
    if not attrs:
        return list(items)
    return [
        item
        for item in items
        if all(_attr_value_matches(item.get(field), needle) for field, needle in attrs.items())
    ]


def panos_object_dicts(objects: list[Any]) -> list[dict[str, Any]]:
    """Convert a list of pan-os-python objects to ``.about()`` dicts.

    Each pan-os-python config object exposes ``.about()`` returning a flat
    dict of its user-facing parameters. We use that as the lean
    representation rather than serializing the whole Python object.
    """
    return [obj.about() for obj in objects]


# --- Write-tool response helpers --------------------------------------------
# These wrap the success/error reporting shape every CRUD tool uses, so the
# response shape stays consistent across object, rule, and admin tools.


def write_success(operation: str, name: str, **extra: Any) -> dict[str, Any]:
    """Lean success response for write tools.

    Keep the shape boring on purpose — the AI doesn't need a verbose object
    dump after a successful create/delete. The caller can read it back with
    a follow-up get_X tool if the post-state matters.
    """
    return {"success": True, "operation": operation, "name": name, **extra}


def wrap_panos_error(err: Exception, operation: str, name: str) -> dict[str, Any]:
    """Convert a pan-os-python exception into our error response shape.

    The error string is run through :func:`redact_secrets` because
    ``pan-python`` and the underlying ``requests`` / ``urllib`` layers can
    embed the full request URL (which carries ``?key=<API_KEY>``) into
    exception messages on TLS or transport failures.  Without this scrub
    the key would be returned verbatim to the AI client and surface in any
    log that captures the tool response.
    """
    return {
        "success": False,
        "operation": operation,
        "name": name,
        "error": redact_exception(err),
    }


def reject_panorama_target(client: Any, operation: str) -> dict[str, Any] | None:
    """Error envelope when a per-firewall runtime tool is pointed at Panorama.

    The dataplane/runtime read tools (interfaces, routing, ARP, DHCP leases,
    IPSec tunnels, GlobalProtect users, User-ID mappings/groups, WildFire
    status, rule hit counts) have no Panorama equivalent — Panorama has no
    data plane, so these operational commands return an empty or error
    response that reads, misleadingly, as "nothing configured". This guard
    turns that into a clean, actionable error pointing the caller at a managed
    firewall. Returns ``None`` when ``client`` is a Firewall so the caller
    proceeds normally.

    The shape mirrors the list-response envelope (``items``/``total``/
    ``count``) the read tools return on success, with an ``error`` describing
    the redirect — so a list-shaped tool stays schema-consistent whether the
    call succeeds or is rejected here. Tools with a different response
    envelope (single-record or custom) should write their own guard.

    Note ``show system resources`` is deliberately NOT routed through this
    guard: Panorama has its own CPU/memory and answers that command, so
    ``get_system_resources`` works against either target.
    """
    from panos.panorama import Panorama

    if isinstance(client, Panorama):
        return {
            "error": (
                f"'{operation}' reads per-firewall runtime/dataplane state, which a "
                "Panorama appliance does not have. Target a managed firewall with the "
                "'firewall' parameter (use list_firewalls or "
                "panorama_get_managed_devices to find one)."
            ),
            "items": [],
            "total": 0,
            "count": 0,
        }
    return None


def reject_serial_log_query(client: Any, operation: str) -> dict[str, Any] | None:
    """Error envelope when a log query is pointed at a serial-through-Panorama target.

    PAN-OS log retrieval (``type=log``) does **not** honor the API ``target``
    serial-redirect the way config and operational commands do. When a log
    query is issued against a firewall reached *through* Panorama by serial,
    Panorama answers it from its own **aggregated log database** instead of the
    named device's local logs — so the caller silently gets fleet-wide logs
    (and IPs masked per the *Panorama* admin role), not the device it asked
    for. That reads as a valid, device-scoped result while being neither.

    This guard detects the serial-proxy client (a ``Firewall`` whose parent is
    a ``Panorama`` — the shape ``_proxied_firewall`` builds) and returns a
    clean, actionable error. Returns ``None`` for a directly-connected
    ``Firewall`` (its own local logs) and for a ``Panorama`` target (querying
    Panorama's aggregated logs directly is legitimate and honest about what it
    returns), so both proceed normally.

    Shape mirrors the log-response envelope (``items``/``total``/``count``) so
    the tool stays schema-consistent whether the call succeeds or is rejected.
    """
    from panos.firewall import Firewall
    from panos.panorama import Panorama

    if isinstance(client, Firewall) and isinstance(getattr(client, "parent", None), Panorama):
        return {
            "error": (
                f"'{operation}' was pointed at a firewall reached through Panorama by "
                "serial redirect, but PAN-OS log queries (type=log) ignore the serial "
                "target — Panorama answers from its aggregated log database, so you would "
                "get fleet-wide logs (masked by the Panorama admin role), not this "
                "device's own logs. To read a specific firewall's local logs, configure a "
                "direct connection to it (a firewalls.json entry with its host + API key) "
                "instead of reaching it by serial through Panorama. To query Panorama's "
                "aggregated logs on purpose, target the Panorama directly."
            ),
            "items": [],
            "total": 0,
            "count": 0,
        }
    return None


# ── Routing engine detection (legacy Virtual Router vs Advanced Routing) ────
# PAN-OS 10.2 introduced the Advanced Routing Engine (ARE), an FRRouting-based
# stack that replaces the legacy Virtual Router. It is enabled per-device and
# changes both the config tree and the operational commands:
#
#   legacy                              ARE
#   /network/virtual-router             /network/logical-router → /vrf
#   <show><routing><route/>             <show><advanced-routing><route/>
#
# The failure this guards against is silent: the *legacy* op command still
# parses on an ARE box, walks an empty legacy RIB, and returns a well-formed
# empty response. No error, nothing to catch — so a route reader reports
# "total: 0" on a firewall with a fully populated ARE RIB, and an LLM caller
# concludes the box has no routes. Detection therefore cannot be
# try-the-command-and-catch; it has to read config state up front.

_ENGINE_CACHE_ATTR = "_panos_mcp_routing_engine"

LOCALHOST_DEVICE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"

ROUTING_ENGINE_ADVANCED = "advanced"
ROUTING_ENGINE_LEGACY = "legacy"
ROUTING_ENGINE_UNKNOWN = "unknown"

# PAN-OS spells the enable flag ``advance-routing`` in the config tree (not
# ``advanced-routing``, as the feature name and op commands do). Rather than
# bet on one spelling, we read the whole ``deviceconfig/setting`` subtree in a
# single call and accept either key.
_ENGINE_FLAG_KEYS = ("advance-routing", "advanced-routing")


def _setting_flag_enabled(result: dict[str, Any]) -> bool:
    """True when ``deviceconfig/setting`` carries a truthy advanced-routing flag."""
    section = result.get("setting", result)
    if not isinstance(section, dict):
        return False
    for key in _ENGINE_FLAG_KEYS:
        value = section.get(key)
        if isinstance(value, str) and value.strip().lower() in ("yes", "true", "1"):
            return True
    return False


def _has_logical_router(result: dict[str, Any]) -> bool:
    """True when ``network/logical-router`` contains at least one entry."""
    section = result.get("logical-router", result)
    if not isinstance(section, dict):
        return False
    entries = section.get("entry")
    return bool(entries) if not isinstance(entries, dict) else True


async def detect_routing_engine(client: Any, *, timeout: float) -> str:
    """Return which routing stack a firewall target runs.

    One of :data:`ROUTING_ENGINE_ADVANCED`, :data:`ROUTING_ENGINE_LEGACY`, or
    :data:`ROUTING_ENGINE_UNKNOWN`.

    Two independent signals, checked in order:

    1. the ``deviceconfig/setting`` advanced-routing flag — authoritative even
       on an ARE box with zero routers configured;
    2. the presence of ``network/logical-router`` entries — corroborates, and
       covers the case where the flag lives at a path this version doesn't use.

    A Panorama target returns ``unknown``: the routing engine is a per-device
    (and, in a Panorama-managed estate, per-template) setting, so there is no
    single answer for the appliance. Callers should omit the field rather than
    report a guess.

    The result is memoized on the client object. ``get_client`` caches clients
    for the process lifetime, so a session pays for detection once per device.
    Detection failures fall back to ``legacy`` — the pre-existing behavior —
    so a probe that can't complete never makes a working firewall worse.
    """
    from panos.errors import PanDeviceError
    from panos.panorama import Panorama

    if isinstance(client, Panorama):
        return ROUTING_ENGINE_UNKNOWN

    cached = getattr(client, _ENGINE_CACHE_ATTR, None)
    if isinstance(cached, str):
        return cached

    probes: tuple[tuple[str, Callable[[dict[str, Any]], bool]], ...] = (
        (f"{LOCALHOST_DEVICE_XPATH}/deviceconfig/setting", _setting_flag_enabled),
        (f"{LOCALHOST_DEVICE_XPATH}/network/logical-router", _has_logical_router),
    )

    engine = ROUTING_ENGINE_LEGACY
    for xpath, is_advanced in probes:
        try:
            result = await run_blocking_timeout(timeout, config_xpath_to_dict, client, xpath)
        except (TimeoutError, PanDeviceError):
            # "No such node" (subtree absent) and slow/unreachable devices both
            # land here — neither is evidence of ARE, so try the next signal.
            continue
        except Exception:
            continue
        if is_advanced(result):
            engine = ROUTING_ENGINE_ADVANCED
            break

    with contextlib.suppress(AttributeError):  # slotted/frozen test double
        setattr(client, _ENGINE_CACHE_ATTR, engine)
    return engine


def reject_are_vr_write(engine: str, operation: str, name: str) -> dict[str, Any] | None:
    """Block a legacy virtual-router write against a firewall running ARE.

    The worst failure in this area is not a misleading read — it's a silent
    no-op write. ``network/virtual-router`` is a valid subtree to *set* on an
    ARE box: the candidate config accepts it and the commit succeeds, but ARE
    never reads it, so the route simply never enters the RIB. The operator is
    told the change landed and it did not. Refuse instead.

    Returns ``None`` on legacy/unknown so existing behavior is untouched.
    """
    if engine != ROUTING_ENGINE_ADVANCED:
        return None
    return {
        "success": False,
        "operation": operation,
        "name": name,
        "error": (
            f"'{operation}' writes to network/virtual-router, but this firewall runs "
            "the Advanced Routing Engine, which ignores that subtree — the commit "
            "would report success and the route would never enter the RIB. "
            "VRF-aware static route writes (network/logical-router) are not yet "
            "supported by this tool; make this change in the PAN-OS UI or CLI."
        ),
    }


async def gather_scoped_objects(
    client: Any, cls: Any, *, timeout: float
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read a modeled object type across every scope of the target, tagged by scope.

    - **Firewall**: a single ``refreshall(client)`` (vsys). Rows are NOT
      scope-tagged, so existing single-scope responses are unchanged.
    - **Panorama**: ``shared`` (refreshall against the Panorama) plus **every
      device group**, with each row tagged by a ``scope`` field (``"shared"``
      or the device-group name). The previous ``refreshall(client)`` read only
      shared and silently omitted every device group.

    Each per-scope read is offloaded and bounded by ``timeout``; a scope that
    times out is skipped and its label collected into ``timed_out`` so one
    stuck device group can neither hang the call nor blank the result. Returns
    ``(rows, timed_out)`` where ``rows`` are ``.about()`` dicts.
    """
    from panos.panorama import DeviceGroup, Panorama

    if not isinstance(client, Panorama):
        objs = await run_blocking_timeout(timeout, cls.refreshall, client)
        return [o.about() for o in objs], []

    rows: list[dict[str, Any]] = []
    timed_out: list[str] = []
    try:
        dgs = await run_blocking_timeout(timeout, DeviceGroup.refreshall, client)
    except TimeoutError:
        return [], ["<device-group enumeration>"]
    scopes: list[tuple[str, Any]] = [("shared", client)]
    scopes.extend((dg.name, dg) for dg in dgs)
    for label, parent in scopes:
        try:
            objs = await run_blocking_timeout(timeout, cls.refreshall, parent)
        except TimeoutError:
            timed_out.append(label)
            continue
        except Exception:
            # The object type isn't valid in this scope — skip rather than fail
            # the whole walk.
            continue
        for o in objs:
            d = o.about()
            d["scope"] = label
            rows.append(d)
    return rows, timed_out


async def gather_template_objects(
    client: Any, refresh_one: Callable[[Any], list[Any]], *, timeout: float
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read template-scoped config across every Panorama template, tagged by source.

    Network/device config (zones, VLANs, virtual routers, …) lives in
    **templates** on a Panorama, not in a firewall-local tree — so the
    firewall-scoped readers see nothing there. This walks every ``Template``
    and reads via the supplied ``refresh_one(parent)`` callback (which knows how
    to fetch its object type from a given parent), tagging each row with the
    source ``template``.

    - **Firewall**: ``refresh_one(client)`` once; rows are NOT tagged.
    - **Panorama**: ``refresh_one(template)`` for every template, each row
      tagged with a ``template`` field.

    Template *stacks* aren't walked separately — their config comes from the
    member templates, which are walked here. Each read is offloaded and bounded;
    a template that times out is skipped and recorded in ``timed_out``. Returns
    ``(rows, timed_out)`` of ``.about()`` dicts.
    """
    from panos.panorama import Panorama, Template

    if not isinstance(client, Panorama):
        objs = await run_blocking_timeout(timeout, refresh_one, client)
        return [o.about() for o in objs], []

    rows: list[dict[str, Any]] = []
    timed_out: list[str] = []
    try:
        templates = await run_blocking_timeout(timeout, Template.refreshall, client)
    except TimeoutError:
        return [], ["<template enumeration>"]
    for tmpl in templates:
        try:
            objs = await run_blocking_timeout(timeout, refresh_one, tmpl)
        except TimeoutError:
            timed_out.append(tmpl.name)
            continue
        except Exception:
            continue
        for o in objs:
            d = o.about()
            d["template"] = tmpl.name
            rows.append(d)
    return rows, timed_out


async def gather_template_config(
    client: Any, sub_xpath: str, *, timeout: float
) -> tuple[list[tuple[str | None, dict[str, Any]]], list[str]]:
    """Read an xpath config subtree across templates (Panorama) or locally (firewall).

    For config types pan-os-python doesn't model (DNS proxy, GlobalProtect,
    User-ID), reading must go through raw xpath. ``sub_xpath`` is the path
    *below* the device node, e.g. ``"network/dns-proxy"`` or
    ``"vsys/entry[@name='vsys1']/global-protect"``.

    - **Firewall**: one fetch against the local device tree; returns
      ``[(None, result)]``.
    - **Panorama**: one fetch per template against that template's config tree;
      returns ``[(template_name, result), ...]`` so the caller can tag entries
      by source template.

    Each fetch is offloaded and bounded by ``timeout``; a template that times
    out is recorded in ``timed_out``, and PAN-OS "No such node" (subtree absent
    in that scope) is skipped. Returns ``(results, timed_out)``.
    """
    from panos.errors import PanDeviceError
    from panos.panorama import Panorama, Template

    device = "/config/devices/entry[@name='localhost.localdomain']"

    async def _fetch(xpath: str) -> dict[str, Any]:
        return await run_blocking_timeout(timeout, config_xpath_to_dict, client, xpath)

    if not isinstance(client, Panorama):
        try:
            result = await _fetch(f"{device}/{sub_xpath}")
        except PanDeviceError as exc:
            if "no such node" in str(exc).lower():
                return [(None, {})], []
            raise
        return [(None, result)], []

    results: list[tuple[str | None, dict[str, Any]]] = []
    timed_out: list[str] = []
    try:
        templates = await run_blocking_timeout(timeout, Template.refreshall, client)
    except TimeoutError:
        return [], ["<template enumeration>"]
    for tmpl in templates:
        xpath = f"{device}/template/entry[@name='{tmpl.name}']{device}/{sub_xpath}"
        try:
            result = await _fetch(xpath)
        except TimeoutError:
            timed_out.append(tmpl.name)
            continue
        except PanDeviceError as exc:
            if "no such node" in str(exc).lower():
                continue
            continue
        results.append((tmpl.name, result))
    return results, timed_out


def redirect_panorama_to_sibling(client: Any, operation: str, *, use: str) -> dict[str, Any] | None:
    """Steer a firewall-scoped *config* read to its Panorama sibling.

    Distinct from :func:`reject_panorama_target` (which guards dataplane/runtime
    tools that have no Panorama equivalent). The tools this guards *do* have a
    Panorama equivalent, but the firewall-scoped version reads the **local
    rulebase**, which is empty on a Panorama target — so it returns a
    misleading "no rules" result. For an LLM that's worse than an error: it
    reads as "nothing configured" and produces a confidently wrong audit (e.g.
    "no SSL decryption in place"). This returns a clean error that *names the
    correct tool* so the agent re-issues against the device-group-aware path.
    Returns ``None`` on a Firewall so the call proceeds normally.

    ``use`` is the human-facing instruction naming the sibling tool(s).
    """
    from panos.panorama import Panorama

    if isinstance(client, Panorama):
        return {
            "error": (
                f"'{operation}' is firewall-scoped — it reads the firewall-local "
                "rulebase, which is empty on a Panorama target, so it would "
                f"misleadingly report no rules. On a Panorama, use {use}."
            ),
            "items": [],
            "total": 0,
            "count": 0,
        }
    return None


async def run_blocking[T](callable_fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a synchronous pan-os-python call in a thread executor.

    pan-os-python is synchronous; ``firewall.commit()``, ``op()``, and
    ``xapi.set()`` block the calling thread. Running them inline in a
    coroutine handler stalls FastMCP's event loop for the call duration —
    which for a commit can be tens of seconds to minutes. Routing them
    through the default thread executor keeps the event loop responsive
    so other tool calls (e.g. progress checks) can proceed.

    Use for any tool that calls pan-os-python in a way that might take
    more than a few hundred milliseconds.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: callable_fn(*args, **kwargs))


# Per-call bound for the multi-call read walkers (rule walker, count, policy
# summary). A single rulebase/object refreshall should return in well under
# this; one that hasn't is treated as a stuck sub-query and skipped rather than
# stalling the whole walk. Kept below the client-level request timeout so an
# abandoned worker thread is reclaimed soon after. Override via
# ``PANOS_READ_TIMEOUT`` (seconds).
_DEFAULT_READ_TIMEOUT = 30.0


def read_timeout() -> float:
    """Per-call read timeout in seconds for the bounded read walkers."""
    raw = os.environ.get("PANOS_READ_TIMEOUT")
    if raw:
        try:
            value = float(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return _DEFAULT_READ_TIMEOUT


async def run_blocking_timeout[T](
    timeout_s: float, callable_fn: Callable[..., T], *args: Any, **kwargs: Any
) -> T:
    """Like :func:`run_blocking`, but abandon the wait after ``timeout_s``.

    Some pan-os-python calls can block far longer than they should — a config
    xpath read that never completes, a device that accepts the connection then
    never answers — and pan-os-python's own per-request timeout is generous
    (we cap it at the client level, but that bound is still tens of seconds).
    For tools where a hang is a known failure mode, wrap the offloaded call
    with a short, asyncio-enforced timeout so the tool returns a clean error
    promptly instead of sitting until the client-level timeout fires.

    Raises :class:`TimeoutError` (``asyncio.TimeoutError`` is an alias on
    3.11+) when the call doesn't finish in time. The worker thread can't be
    force-killed, so it keeps running until the call's own (lower, client-level)
    timeout releases it; its result is then discarded. Keep ``timeout_s`` well
    below the client-level request timeout so the orphaned thread is reclaimed
    soon after.
    """
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(None, lambda: callable_fn(*args, **kwargs))
    return await asyncio.wait_for(fut, timeout=timeout_s)


__all__ = [
    "LOCALHOST_DEVICE_XPATH",
    "ROUTING_ENGINE_ADVANCED",
    "ROUTING_ENGINE_LEGACY",
    "ROUTING_ENGINE_UNKNOWN",
    "AttrFilter",
    "ToolContext",
    "check_renamed_attr_keys",
    "config_xpath_to_dict",
    "detect_routing_engine",
    "element_to_dict",
    "emit_preflight_audit",
    "enrich_security_rule_dicts",
    "filter_by_attrs",
    "gather_scoped_objects",
    "gather_template_config",
    "gather_template_objects",
    "op_to_dict",
    "panos_object_dicts",
    "read_timeout",
    "redirect_panorama_to_sibling",
    "reject_are_vr_write",
    "reject_panorama_target",
    "reject_serial_log_query",
    "run_blocking",
    "run_blocking_timeout",
    "wrap_panos_error",
    "write_success",
]
