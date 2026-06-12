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
"""Charset allowed by PAN-OS for object/rule names. Same regex as the TS fork."""


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


__all__ = ["PANOS_NAME_PATTERN", "PanosDescription", "PanosName", "PanosTagName"]
