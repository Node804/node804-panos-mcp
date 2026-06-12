"""Hand-rolled XML helpers for rule types pan-os-python doesn't model.

Currently used by QoS rule CRUD. pan-os-python 1.12.5 has no ``QosRule``
class, so we fall back to ``firewall.xapi.set/delete/move`` with hand-built
element strings.

All values are XML-escaped defensively. Inputs are already validated by
Pydantic at the tool layer (PanosName regex, MemberValue length cap), but
escaping at construction time is cheap insurance against future schema
relaxations.

When pan-os-python adds first-class QoS modeling, this module becomes
deletable.
"""

from __future__ import annotations

from collections.abc import Iterable
from xml.sax.saxutils import escape, quoteattr


def xml_escape_text(value: str) -> str:
    """Escape XML special characters in element text content."""
    return escape(value)


def xml_escape_attr(value: str) -> str:
    """Escape and quote an attribute value (returns the value WITH quotes)."""
    return quoteattr(value)


def _members(items: Iterable[str]) -> str:
    """Build a series of ``<member>VALUE</member>`` elements with escaped values."""
    return "".join(f"<member>{xml_escape_text(v)}</member>" for v in items)


def build_qos_rule_xml(
    *,
    name: str,
    from_zones: list[str],
    to_zones: list[str],
    source: list[str],
    destination: list[str],
    application: list[str],
    service: list[str],
    action_class: str,
    description: str | None = None,
    disabled: bool | None = None,
) -> str:
    """Build a QoS rule ``<entry>`` element XML string.

    Inputs should already be validated by Pydantic (PanosName, MemberValue);
    we additionally XML-escape every interpolated value as defense in depth.
    """
    parts: list[str] = [f"<entry name={xml_escape_attr(name)}>"]
    parts.append(f"<from>{_members(from_zones)}</from>")
    parts.append(f"<to>{_members(to_zones)}</to>")
    parts.append(f"<source>{_members(source)}</source>")
    parts.append(f"<destination>{_members(destination)}</destination>")
    parts.append(f"<application>{_members(application)}</application>")
    parts.append(f"<service>{_members(service)}</service>")
    parts.append(f"<action><class>{xml_escape_text(action_class)}</class></action>")
    if description:
        parts.append(f"<description>{xml_escape_text(description)}</description>")
    if disabled is not None:
        parts.append(f"<disabled>{'yes' if disabled else 'no'}</disabled>")
    parts.append("</entry>")
    return "".join(parts)


QOS_RULES_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
    "/rulebase/qos/rules"
)
"""XPath to the QoS rulebase. Constant — assumes the default single-vsys layout."""


def qos_rule_xpath(rule_name: str) -> str:
    """Build the XPath for a specific QoS rule entry.

    Rule names are validated by PanosName (no apostrophes, no XPath
    metacharacters) so direct interpolation is safe.
    """
    return f"{QOS_RULES_XPATH}/entry[@name='{rule_name}']"


__all__ = [
    "QOS_RULES_XPATH",
    "build_qos_rule_xml",
    "qos_rule_xpath",
    "xml_escape_attr",
    "xml_escape_text",
]
