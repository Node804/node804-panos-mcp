"""Defense-in-depth guards for the raw-config and raw-op escape hatches.

``set_config``, ``delete_config``, and ``run_op_command`` accept arbitrary
PAN-OS XPath / XML and arbitrary operational commands respectively.  They
exist because there's no realistic way to model every PAN-OS config field
or op command as a typed tool, but they're also the most dangerous calls
in the suite — at ADMIN mode, a malicious or hallucinating client could:

* create a new superuser admin under ``/config/mgt-config/users``
* replace the trust-store certificate at ``/config/shared/certificate``
* reboot the box with ``<request><restart><system></system></restart></request>``
* factory-reset with ``<request><system><private-data-reset>...``
* push a malicious config to managed firewalls

This module adds two complementary defenses:

1. **Registration gating** — the raw tools only register when the operator
   has explicitly set ``PANOS_ENABLE_RAW_CONFIG=true`` (config) or
   ``PANOS_ENABLE_RAW_OPS=true`` (op commands).  Default is *not registered*,
   so a misconfigured ADMIN mode can't expose them by accident.

2. **Subtree / verb denylists** — even when registered, calls into known
   dangerous areas (auth, certificates, HA, system reset) are rejected at
   tool entry with a clear error.  An optional allow-list env var lets the
   operator restrict the surface further to a specific subtree.

Both checks emit a stderr WARNING with the rejected target so that an
attempted misuse is visible in operator logs even when no separate audit
sink is configured.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Final

# --- Environment-driven feature flags -------------------------------------


def raw_config_enabled() -> bool:
    """True iff ``PANOS_ENABLE_RAW_CONFIG`` is set to a truthy value.

    Evaluated at registration time, not per-call: the operator opts in at
    server start.  Accepts ``true``/``1``/``yes`` (case-insensitive).
    """
    return os.environ.get("PANOS_ENABLE_RAW_CONFIG", "").strip().lower() in {
        "true", "1", "yes",
    }


def raw_ops_enabled() -> bool:
    """True iff ``PANOS_ENABLE_RAW_OPS`` is set to a truthy value.

    Mirrors :func:`raw_config_enabled` for the op-command escape hatch.
    """
    return os.environ.get("PANOS_ENABLE_RAW_OPS", "").strip().lower() in {
        "true", "1", "yes",
    }


# --- XPath denylist -------------------------------------------------------

# Subtrees that ``set_config`` / ``delete_config`` must never touch.  Each
# pattern is matched as a substring against the xpath (case-sensitive — PAN-OS
# xpath element names are case-sensitive).  The set is small and conservative;
# operators who legitimately need to manage one of these subtrees should
# use a dedicated tool or accept the risk and remove the entry locally.
_DENIED_XPATH_SUBSTRINGS: Final[tuple[str, ...]] = (
    # Admin user accounts — a write here creates/deletes superusers.
    "/mgt-config",
    "/mgt-config/users",
    # Authentication / authorization machinery.
    "/shared/authentication-profile",
    "/shared/authentication-sequence",
    "/shared/admin-role",
    # Trust-store and SSL/TLS material.
    "/shared/certificate",
    "/shared/certificate-profile",
    "/shared/ssl-decrypt",
    # High-availability — flipping HA state can split-brain a pair.
    "/deviceconfig/high-availability",
    # System reset / wipe / debug bootstrap.
    "/deviceconfig/system/panorama",  # remove Panorama management — lockout risk
)


def _check_xpath_denylist(xpath: str) -> str | None:
    """Return a rejection reason if ``xpath`` hits the denylist, else None."""
    norm = xpath.strip()
    for needle in _DENIED_XPATH_SUBSTRINGS:
        if needle in norm:
            return (
                f"xpath '{xpath}' touches a protected subtree ('{needle}'). "
                "Use a dedicated tool, or modify this config out-of-band."
            )
    return None


def _check_xpath_allowlist(xpath: str) -> str | None:
    """If ``PANOS_RAW_XPATH_ALLOW`` is set, require xpath to start with one
    of its (comma-separated) prefixes.  When unset, all non-denied xpaths
    are allowed.
    """
    raw = os.environ.get("PANOS_RAW_XPATH_ALLOW", "").strip()
    if not raw:
        return None
    prefixes = tuple(p.strip() for p in raw.split(",") if p.strip())
    if not prefixes:
        return None
    if not any(xpath.startswith(p) for p in prefixes):
        return (
            f"xpath '{xpath}' is not under the allow-list "
            f"(PANOS_RAW_XPATH_ALLOW={raw!r})."
        )
    return None


def check_raw_xpath(xpath: str) -> str | None:
    """Validate an xpath for ``set_config`` / ``delete_config``.

    Returns the rejection reason as a string when the xpath should be
    refused, or ``None`` when the call may proceed.  Emits a stderr
    WARNING on rejection so the attempt is visible even without an audit
    sink.
    """
    reason = _check_xpath_denylist(xpath) or _check_xpath_allowlist(xpath)
    if reason is not None:
        print(f"[panos-mcp] BLOCKED raw-config call: {reason}", file=sys.stderr)
    return reason


# --- Op-command denylist --------------------------------------------------

# Operational commands that ``run_op_command`` must never execute.  Matched
# as case-insensitive regex against the raw XML payload.  Covers the obvious
# destructive verbs; ``<show>`` commands are not on the list because they
# are read-only and the original tool surface depended on them.
_DENIED_OP_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # System lifecycle.
    re.compile(r"<request>\s*<shutdown\b", re.IGNORECASE),
    re.compile(r"<request>\s*<restart\b", re.IGNORECASE),
    re.compile(r"<request>\s*<system>\s*<private-data-reset\b", re.IGNORECASE),
    re.compile(r"<request>\s*<system>\s*<factory-reset\b", re.IGNORECASE),
    re.compile(r"<request>\s*<reboot\b", re.IGNORECASE),
    # Software install / content update — out-of-band only.
    re.compile(r"<request>\s*<system>\s*<software>", re.IGNORECASE),
    re.compile(r"<request>\s*<content>\s*<upgrade\b", re.IGNORECASE),
    re.compile(r"<request>\s*<anti-virus>\s*<upgrade\b", re.IGNORECASE),
    re.compile(r"<request>\s*<wildfire>\s*<upgrade\b", re.IGNORECASE),
    # Debug surface — a generic block to discourage diagnostics-as-attack.
    re.compile(r"<debug\b", re.IGNORECASE),
    # Password / key manipulation.
    re.compile(r"<request>\s*<password-hash\b", re.IGNORECASE),
    re.compile(r"<set>\s*<password\b", re.IGNORECASE),
)

# Whitelist regex for "show-only" mode used by the read variant of the tool.
_SHOW_ONLY_RE: Final = re.compile(r"^\s*<show\b", re.IGNORECASE)


def check_op_command(command: str) -> str | None:
    """Validate an op command for ``run_op_command`` (admin variant).

    Returns the rejection reason when the command should be refused, or
    ``None`` to allow it.  Like :func:`check_raw_xpath` this logs blocked
    attempts to stderr.
    """
    norm = command.strip()
    for pat in _DENIED_OP_PATTERNS:
        if pat.search(norm):
            reason = (
                f"op command matches denied pattern '{pat.pattern}'. "
                "Reboot, software install, debug, and credential mutation "
                "commands are not exposed through the MCP."
            )
            # Log only the first 200 chars of the command to avoid noisy
            # stderr — the audit sink (if configured) will hold the full.
            head = norm[:200] + ("…" if len(norm) > 200 else "")
            print(
                f"[panos-mcp] BLOCKED op call: {reason} (command head: {head!r})",
                file=sys.stderr,
            )
            return reason
    return None


def is_show_command(command: str) -> bool:
    """True iff ``command`` begins with ``<show ...>`` (read-only)."""
    return bool(_SHOW_ONLY_RE.match(command))


__all__ = [
    "check_op_command",
    "check_raw_xpath",
    "is_show_command",
    "raw_config_enabled",
    "raw_ops_enabled",
]
