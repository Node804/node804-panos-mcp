"""Secret-redaction helpers for error messages and log lines.

PAN-OS API calls authenticate with a long-lived API key passed as a URL
query parameter (``?key=<API_KEY>``).  The underlying ``pan-python`` and
``requests`` libraries occasionally surface the request URL in exception
strings, response bodies, and debug logs — most notably on TLS handshake
failures and unparseable responses where the full ``self.uri`` is echoed
back.  An MCP host that captures stderr into a log aggregator would then
hold the key indefinitely.

This module provides a single ``redact_secrets`` function that strips any
``key=<value>`` (and ``api_key=<value>``) query parameter from arbitrary
text.  Every code path that turns an exception into a log line or a tool
response runs the result through here.

The redaction is intentionally conservative — it only replaces the value,
leaves surrounding context intact so log readers can still see where the
event happened, and is regex-only so there's no parsing surface to abuse.
"""

from __future__ import annotations

import re
from typing import Final

# Match `key=` / `api_key=` / `api-key=` (case-insensitive) followed by a
# value that runs until the next URL/whitespace separator or quote.  The
# leading separator (``?`` or ``&``) is preserved so the surrounding URL
# remains visually intact.
_KEY_PARAM_RE: Final = re.compile(
    r"(?P<sep>[?&])(?P<name>(?:api[-_]?)?key)=(?P<val>[^&\s'\"<>]+)",
    flags=re.IGNORECASE,
)

# Catch bare assignments like ``api_key=AQ...`` that appear in repr() output
# without a URL prefix.  Word boundary on the left, value runs to the next
# whitespace, comma, paren, or quote.
_BARE_KEY_RE: Final = re.compile(
    r"\b(?P<name>api[-_]?key)\s*[=:]\s*['\"]?(?P<val>[A-Za-z0-9+/=_\-]{16,})['\"]?",
    flags=re.IGNORECASE,
)

REDACTED: Final = "***REDACTED***"


def redact_secrets(text: str) -> str:
    """Strip API-key values from a string while preserving surrounding text.

    Safe to call on any string — if no secret patterns match, the input is
    returned unchanged.  Designed to be cheap enough to apply liberally on
    every error path.
    """
    if not text:
        return text
    text = _KEY_PARAM_RE.sub(
        lambda m: f"{m.group('sep')}{m.group('name')}={REDACTED}", text
    )
    text = _BARE_KEY_RE.sub(
        lambda m: f"{m.group('name')}={REDACTED}", text
    )
    return text


def redact_exception(exc: BaseException) -> str:
    """Render an exception as a redacted string suitable for logs/responses.

    Falls back to the class name when ``str(exc)`` is empty (matches the
    behavior of ``wrap_panos_error`` for consistency).
    """
    return redact_secrets(str(exc)) or exc.__class__.__name__


__all__ = ["REDACTED", "redact_exception", "redact_secrets"]
