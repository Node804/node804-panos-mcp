"""``pan-os-python`` client factory with caching and TLS plumbing.

Each tool calls :func:`get_client` with a target name; the registry resolves
the host + api_key, the factory constructs a ``Firewall`` or ``Panorama``
instance with the active TLS config, and the result is cached for the
lifetime of the server process.

Built on ``pan-os-python``: config operations are object-method calls
(``firewall.refresh_system_info()``, ``firewall.add(AddressObject(...))``)
rather than hand-built XPath strings, so the MCP layer stays focused on
response shaping and access control.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from mcp_toolkit import TlsConfig
from panos.firewall import Firewall
from panos.panorama import Panorama

from .config.firewalls import FirewallEntry, resolve_firewall


@dataclass(frozen=True)
class ResolveError:
    """Returned when a tool requested a target that can't be resolved.

    Tools surface ``ResolveError.message`` to the AI rather than raising,
    so the model gets a clean error string instead of a stack trace.
    """

    message: str


_CLIENTS: dict[str, Firewall | Panorama] = {}
"""Cache of constructed clients keyed by entry name. Lifetime = server process."""


def _tls_kwargs(tls: TlsConfig) -> dict[str, Any]:
    """Build the ``verify`` kwarg for pan-os-python from our TLS config."""
    if not tls.verify:
        return {"verify": False}
    if tls.ca_path is not None and tls.ca_bundle is not None:
        return {"verify": str(tls.ca_path)}
    return {}


def _build_client(entry: FirewallEntry, tls: TlsConfig) -> Firewall | Panorama:
    """Construct the correct ``pan-os-python`` client for the entry.

    Connects as a ``Firewall`` first, calls ``refresh_system_info()`` to
    detect the device type, and rebuilds as ``Panorama`` when the model
    indicates a Panorama appliance (model == "Panorama" or starts with
    "M-").  The detected type is cached for the server lifetime.
    """
    base_kwargs: dict[str, Any] = {
        "hostname": entry.host,
        "api_key": entry.api_key,
        **_tls_kwargs(tls),
    }
    client: Firewall | Panorama = Firewall(**base_kwargs)
    try:
        version, model, serial = client.refresh_system_info()
    except Exception as exc:
        print(
            f"[panos-mcp] WARNING: system-info probe failed for '{entry.name}' "
            f"({exc}); treating as Firewall.",
            file=sys.stderr,
        )
        return client

    if model == "Panorama" or (model and model.startswith("M-")):
        client = Panorama(**base_kwargs)
        client._set_version_and_version_info(version)
        print(
            f"[panos-mcp] Detected Panorama ({model}) for '{entry.name}'",
            file=sys.stderr,
        )
    else:
        client.serial = serial
        print(
            f"[panos-mcp] Detected Firewall ({model}) for '{entry.name}'",
            file=sys.stderr,
        )
    return client


def get_client(
    name: str | None,
    *,
    tls: TlsConfig,
) -> Firewall | Panorama | ResolveError:
    """Return a cached client for the named target.

    Returns :class:`ResolveError` instead of raising so tools can surface a
    clean message to the AI without try/except boilerplate.
    """
    entry = resolve_firewall(name)
    if entry is None:
        if name is None:
            return ResolveError(
                "No firewall configured. Set PANOS_HOST/PANOS_API_KEY or "
                "create a firewalls.json with at least one entry."
            )
        return ResolveError(
            f"Firewall '{name}' not found. Use list_firewalls to see configured targets."
        )

    cached = _CLIENTS.get(entry.name)
    if cached is not None:
        return cached

    client = _build_client(entry, tls)
    _CLIENTS[entry.name] = client
    return client


def reset_client_cache() -> None:
    """Drop all cached clients. Used by tests; rarely needed at runtime."""
    _CLIENTS.clear()


def probe_client(
    name: str | None,
    *,
    tls: TlsConfig,
) -> dict[str, Any]:
    """Light-touch metadata for ``server_status``: confirms a target resolves.

    Does NOT make an outbound API call — that would slow startup and
    introduce a network dependency for a status tool. Just confirms the
    config-side resolution chain works.
    """
    client = get_client(name, tls=tls)
    if isinstance(client, ResolveError):
        return {"resolved": False, "error": client.message}
    return {
        "resolved": True,
        "host": client.hostname,
        "class": type(client).__name__,
    }


__all__ = [
    "ResolveError",
    "get_client",
    "probe_client",
    "reset_client_cache",
]
