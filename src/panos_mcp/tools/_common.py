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

from dataclasses import dataclass
from typing import Any
from xml.etree.ElementTree import Element

from mcp.server.fastmcp import FastMCP
from mcp_toolkit import ModeGate, TlsConfig

from ..client import ResolveError, get_client


@dataclass(frozen=True)
class ToolContext:
    """Cross-cutting state passed to every ``register_*_tools`` function.

    The server builds one of these at startup; tool modules use it to
    decorate handlers (``ctx.gate.tool(ctx.mcp, ...)``) and resolve clients
    (``ctx.resolve(firewall)``).
    """

    mcp: FastMCP
    gate: ModeGate
    tls: TlsConfig

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


def element_to_dict(element: Element | None) -> dict[str, Any]:
    """Convert an ElementTree.Element to a plain dict.

    Conversion rules (matches what fast-xml-parser produces in the TS fork):
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


def op_to_dict(client: Any, cmd: str) -> dict[str, Any]:
    """Run a PAN-OS op command and return its ``<result>`` content as a dict.

    Wraps ``client.op(cmd)`` and unwraps the standard
    ``<response status="success"><result>...</result></response>`` envelope.
    Returns ``{}`` when the response has no result element.

    Tests can mock ``client.op`` to return a dict directly; this function
    handles both real Element responses and pre-converted dicts.
    """
    response = client.op(cmd)
    if isinstance(response, dict):
        return response
    if isinstance(response, Element):
        result = response.find("./result")
        return element_to_dict(result)
    return {}


def panos_object_dicts(objects: list[Any]) -> list[dict[str, Any]]:
    """Convert a list of pan-os-python objects to ``.about()`` dicts.

    Each pan-os-python config object exposes ``.about()`` returning a flat
    dict of its user-facing parameters. We use that as the lean
    representation rather than serializing the whole Python object.
    """
    return [obj.about() for obj in objects]


__all__ = [
    "ToolContext",
    "element_to_dict",
    "op_to_dict",
    "panos_object_dicts",
]
