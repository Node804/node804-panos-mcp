"""``pan-os-python`` client factory with caching and TLS plumbing.

Each tool calls :func:`get_client` with a target name; the registry resolves
the host + api_key, the factory constructs a ``Firewall`` or ``Panorama``
instance with the active TLS config, and the result is cached for the
lifetime of the server process.

The TS fork built every URL by hand. We use ``pan-os-python`` so config
operations are object-method calls (``firewall.refresh_system_info()``,
``firewall.add(AddressObject(...))``) instead of XPath strings.

Phase 2 only exposes the factory and a ``probe()`` helper used by the
``server_status`` tool. Read/write tools come online in Phase 3+.
"""

from __future__ import annotations

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


def _build_client(entry: FirewallEntry, tls: TlsConfig) -> Firewall | Panorama:
    """Construct a ``pan-os-python`` Firewall (default) for the entry.

    We start every target as a ``Firewall``; ``Panorama`` instances are
    auto-detected by issuing ``show system info`` and inspecting the model
    field once Phase 3 tools come online. For now Phase 2 doesn't need to
    distinguish — both classes share the constructor signature we use here.

    The ``verify`` and CA bundle flow into ``pan-os-python``'s underlying
    ``requests`` session via the constructor's ``port``-adjacent kwargs.
    Modern ``pan-os-python`` accepts ``verify`` directly.
    """
    fw_kwargs: dict[str, Any] = {
        "hostname": entry.host,
        "api_key": entry.api_key,
    }
    # pan-os-python forwards kwargs to its xapi.PanXapi which honors verify.
    # When custom CA is provided, requests accepts a path string for verify;
    # use the env var path because TlsConfig stores it on disk already.
    if not tls.verify:
        fw_kwargs["verify"] = False
    elif tls.ca_path is not None and tls.ca_bundle is not None:
        # requests accepts a path for verify to use a custom CA bundle.
        fw_kwargs["verify"] = str(tls.ca_path)
    # Default (verify=True, no custom CA): omit the kwarg so pan-os-python
    # uses its default trust store.
    return Firewall(**fw_kwargs)


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
