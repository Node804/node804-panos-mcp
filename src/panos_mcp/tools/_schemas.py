"""Shared Pydantic input types for write tools.

PAN-OS object/rule names share a charset (letters, digits, dot, underscore,
hyphen, space) that we enforce at the schema layer. Validation here defends
against XPath injection and matches what PAN-OS itself accepts — typos that
PAN-OS would reject anyway are caught client-side before a wasted round-trip.

Tag names allow up to 127 chars (vs 63 for everything else); other fields
follow PAN-OS limits as documented.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

PANOS_NAME_PATTERN = r"^[A-Za-z0-9._\- ]+$"
"""Charset allowed by PAN-OS for object/rule names."""


PanosName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=63,
        pattern=PANOS_NAME_PATTERN,
        description=(
            "PAN-OS object/rule name. Letters, digits, dot, underscore, hyphen, "
            "and space only. Max 63 characters."
        ),
    ),
]


PanosTagName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=127,
        pattern=PANOS_NAME_PATTERN,
        description="PAN-OS tag name. Same charset as object names; max 127 characters.",
    ),
]


PanosDescription = Annotated[
    str,
    Field(
        max_length=1023,
        description="Optional free-form description (max 1023 characters).",
    ),
]


# --- Rule input types -------------------------------------------------------
# These are shared across rule-CRUD tools so input contracts stay consistent
# between security, NAT, PBF, QoS, and decryption rules.


MemberValue = Annotated[
    str,
    Field(
        min_length=1,
        max_length=255,
        description=(
            "A member of a rule list field (zone, address, application, "
            "service). May be a PAN-OS object/group name or the special "
            "literal 'any'. Object names that contain characters outside "
            "the PAN-OS-safe charset will be rejected by the firewall."
        ),
    ),
]
"""Loose type for rule member values.

Unlike :data:`PanosName`, this allows the literal ``"any"`` plus inline
address strings ("10.0.0.0/24") and application/service names that the
firewall already validates server-side. XML construction in rule tools
applies escapeXml-equivalent escaping defensively.
"""


MemberList = Annotated[
    list[MemberValue],
    Field(min_length=1, description="At least one member value."),
]


__all__ = [
    "PANOS_NAME_PATTERN",
    "MemberList",
    "MemberValue",
    "PanosDescription",
    "PanosName",
    "PanosTagName",
]
