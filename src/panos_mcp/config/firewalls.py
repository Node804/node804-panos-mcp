"""Multi-firewall registry for panos-mcp.

Two configuration sources, in priority order:

1. ``firewalls.json`` (location: ``$PANOS_FIREWALLS_CONFIG`` or
   ``~/.config/panos-mcp/firewalls.json``) — a list of named firewall
   targets. API keys live in the OS keychain (via the ``keyring`` package);
   the JSON file holds only ``name`` and ``host``. Plaintext ``api_key``
   fields in older configs are auto-migrated to the keychain on first load
   and the JSON is rewritten without them.
2. ``PANOS_HOST`` + ``PANOS_API_KEY`` env vars — single-firewall fallback
   used when no JSON file is present.

The file is always written with mode ``0o600`` on POSIX (best-effort on
Windows) so plaintext fallback keys aren't world-readable.

Public API:
    load_firewall_config()              # initialize on startup
    resolve_firewall(name=None)         # look up a target
    is_multi_firewall()                 # True when >1 entry configured
    list_firewall_entries()             # name+host pairs (never keys)
    save_firewall_entry(entry)          # write a new/updated entry
"""

from __future__ import annotations

import json
import os
import re
import sys
from contextlib import suppress
from pathlib import Path
from typing import Final

import keyring
from pydantic import BaseModel, ConfigDict, Field, field_validator

KEYRING_SERVICE: Final = "panos-mcp"
"""Service name used for OS keychain entries."""


_PANOS_NAME_REGEX = re.compile(r"^[A-Za-z0-9._\- ]+$")
"""PAN-OS-safe name charset. Defends against XPath injection and matches what
PAN-OS itself accepts for object/firewall identifiers."""


class FirewallEntry(BaseModel):
    """In-memory representation of a configured firewall target.

    The ``api_key`` field is populated only when the entry has been resolved
    against the keychain (or env-var fallback). Persisted JSON entries
    contain only ``name`` and ``host``.
    """

    name: str = Field(min_length=1, max_length=63)
    host: str = Field(min_length=1)
    api_key: str | None = None

    model_config = ConfigDict(frozen=True)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not _PANOS_NAME_REGEX.match(v):
            raise ValueError(
                "Firewall name must contain only letters, digits, dot, "
                "underscore, hyphen, or space."
            )
        return v

    @field_validator("host")
    @classmethod
    def _normalize_host(cls, v: str) -> str:
        # Strip http(s):// prefix and trailing slashes — keeps the API
        # client's URL construction simple and predictable.
        cleaned = v.strip()
        cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.rstrip("/")
        if not cleaned:
            raise ValueError("Firewall host cannot be empty after normalization.")
        return cleaned


class _FileEntry(BaseModel):
    """Schema of a single entry as stored in firewalls.json on disk."""

    name: str
    host: str
    api_key: str | None = None  # legacy; auto-migrated to keychain on load

    model_config = ConfigDict(extra="ignore")


class _FileSchema(BaseModel):
    firewalls: list[_FileEntry] = Field(default_factory=list)


# --- Module-level state -----------------------------------------------------
# Populated by load_firewall_config() at startup. The registry is global
# because tools resolve targets ad hoc and a singleton avoids passing it
# through every call site.

_entries: list[FirewallEntry] = []
"""Currently loaded entries with api_key populated."""


def get_config_path() -> Path:
    """Resolve the firewalls.json path from env or default location."""
    raw = os.environ.get("PANOS_FIREWALLS_CONFIG", "").strip()
    if raw:
        return Path(raw)
    return Path.home() / ".config" / "panos-mcp" / "firewalls.json"


def load_firewall_config() -> None:
    """Initialize the registry from disk + keychain + env fallback.

    Called once at server startup. Subsequent reads use the cached state.
    Idempotent: calling twice replaces the existing state with a fresh load.
    """
    global _entries

    path = get_config_path()
    raw_text: str | None = None
    with suppress(OSError):
        raw_text = path.read_text(encoding="utf-8")

    if raw_text is None:
        _entries = []
        return

    parsed = _FileSchema.model_validate(json.loads(raw_text))
    file_entries = [
        _FileEntry(
            name=e.name,
            host=_normalize_host_str(e.host),
            api_key=e.api_key,
        )
        for e in parsed.firewalls
    ]

    # Auto-migrate any plaintext api_keys to the keychain. Mirrors the TS
    # fork's behavior so users transitioning between implementations don't
    # need to re-enroll keys.
    to_migrate = [e for e in file_entries if e.api_key]
    if to_migrate and _keyring_available():
        try:
            for e in to_migrate:
                assert e.api_key is not None
                keyring.set_password(KEYRING_SERVICE, e.name, e.api_key)
            cleaned = {
                "firewalls": [{"name": e.name, "host": e.host} for e in file_entries]
            }
            _write_restricted(path, json.dumps(cleaned, indent=2) + "\n")
            print(
                f"[panos-mcp] Migrated {len(to_migrate)} API key(s) to system keychain",
                file=sys.stderr,
            )
            # After migration, plaintext keys are gone from the file and the
            # keychain holds the authoritative copies.
            file_entries = [
                _FileEntry(name=e.name, host=e.host, api_key=None) for e in file_entries
            ]
        except Exception as err:
            # Redact in case the underlying keyring backend echoed a key
            # value (some backends raise with the offending value in tow).
            from .._redact import redact_exception

            print(
                f"[panos-mcp] WARNING: keychain migration failed "
                f"({redact_exception(err)}). Keys remain in plaintext.",
                file=sys.stderr,
            )

    resolved: list[FirewallEntry] = []
    for fe in file_entries:
        api_key = fe.api_key  # plaintext fallback for headless servers
        if _keyring_available():
            kc = keyring.get_password(KEYRING_SERVICE, fe.name)
            if kc:
                api_key = kc
        if not api_key:
            print(
                f"[panos-mcp] WARNING: no keychain entry for firewall '{fe.name}' "
                "— it will be unavailable until a key is set.",
                file=sys.stderr,
            )
            continue
        resolved.append(FirewallEntry(name=fe.name, host=fe.host, api_key=api_key))

    _entries = resolved


def resolve_firewall(name: str | None = None) -> FirewallEntry | None:
    """Resolve a firewall target.

    Resolution order:
      1. If ``name`` is given, return that entry (or None when not found).
      2. Else if exactly one entry is configured, return it.
      3. Else fall back to ``PANOS_HOST`` + ``PANOS_API_KEY`` env vars.
      4. Else return None.

    Multi-firewall mode (>1 entry) requires the caller to specify ``name``;
    we deliberately don't pick a default to avoid silently targeting the
    wrong firewall.
    """
    if name is not None:
        for e in _entries:
            if e.name == name:
                return e
        return None

    if len(_entries) == 1:
        return _entries[0]

    if len(_entries) > 1:
        return None

    # No JSON config — env-var fallback for single-firewall use.
    host = _normalize_host_str(os.environ.get("PANOS_HOST", ""))
    api_key = os.environ.get("PANOS_API_KEY", "").strip()
    if host and api_key:
        return FirewallEntry(name="env", host=host, api_key=api_key)
    return None


def is_multi_firewall() -> bool:
    """True when multiple firewall entries are configured.

    When True, every tool that talks to a firewall must take an explicit
    ``firewall: str`` argument — there's no default to pick.
    """
    return len(_entries) > 1


def list_firewall_entries() -> list[dict[str, str]]:
    """Return ``{name, host}`` pairs for every configured entry. Never returns keys."""
    return [{"name": e.name, "host": e.host} for e in _entries]


def save_firewall_entry(entry: FirewallEntry) -> None:
    """Persist a new or updated entry to disk + keychain.

    The api_key is stored in the keychain when available; otherwise it goes
    to the JSON file with a stderr warning. The file is written with mode
    ``0o600``.
    """
    assert entry.api_key, "save_firewall_entry requires api_key on the entry"

    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Read current state (if any), update, write back.
    config: dict[str, list[dict[str, str | None]]] = {"firewalls": []}
    with suppress(OSError, json.JSONDecodeError):
        config = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(config.get("firewalls"), list):
            config = {"firewalls": []}

    if _keyring_available():
        keyring.set_password(KEYRING_SERVICE, entry.name, entry.api_key)
        new_record: dict[str, str | None] = {"name": entry.name, "host": entry.host}
    else:
        print(
            "[panos-mcp] WARNING: keychain unavailable; storing api_key in plaintext "
            f"in {path}. File will be chmod'd to 0o600.",
            file=sys.stderr,
        )
        new_record = {"name": entry.name, "host": entry.host, "api_key": entry.api_key}

    firewalls = config["firewalls"]
    for i, existing in enumerate(firewalls):
        if existing.get("name") == entry.name:
            firewalls[i] = new_record
            break
    else:
        firewalls.append(new_record)

    _write_restricted(path, json.dumps(config, indent=2) + "\n")

    # Update in-memory state so the new entry is immediately resolvable.
    global _entries
    _entries = [e for e in _entries if e.name != entry.name]
    _entries.append(entry)


# --- Internals --------------------------------------------------------------


def _keyring_available() -> bool:
    """True when the ``keyring`` backend can store/retrieve passwords.

    Detects headless Linux servers (no ``libsecret``) where the default
    ``keyring`` backend raises on use. We probe with a no-op read; if it
    raises, we fall back to plaintext storage in firewalls.json.
    """
    try:
        keyring.get_password(KEYRING_SERVICE, "__availability_test__")
        return True
    except Exception:
        return False


def _normalize_host_str(host: str) -> str:
    """Strip scheme + trailing slashes from a hostname string."""
    cleaned = host.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    return cleaned.rstrip("/")


def _write_restricted(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` with mode ``0o600``.

    Always re-applies chmod after write because the ``mode`` argument to
    ``open()`` only affects new files. On Windows this is best-effort and
    typically a no-op against ACLs.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        os.close(fd) if fd >= 0 else None
        raise
    with suppress(OSError):
        os.chmod(path, 0o600)


__all__ = [
    "KEYRING_SERVICE",
    "FirewallEntry",
    "get_config_path",
    "is_multi_firewall",
    "list_firewall_entries",
    "load_firewall_config",
    "resolve_firewall",
    "save_firewall_entry",
]
