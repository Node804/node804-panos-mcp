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


__all__ = [
    "AttrFilter",
    "ToolContext",
    "check_renamed_attr_keys",
    "element_to_dict",
    "emit_preflight_audit",
    "enrich_security_rule_dicts",
    "filter_by_attrs",
    "op_to_dict",
    "panos_object_dicts",
    "run_blocking",
    "wrap_panos_error",
    "write_success",
]
