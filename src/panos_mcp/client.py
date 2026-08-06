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

import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from xml.etree.ElementTree import Element

from node804_mcp_toolkit import TlsConfig
from panos.firewall import Firewall
from panos.panorama import Panorama

from ._redact import redact_exception
from .config.firewalls import (
    SERIAL_CONNECTION_ENV,
    FirewallEntry,
    list_firewall_entries,
    resolve_firewall,
    serial_connection_enabled,
)

# pan-os-python defaults its per-HTTP-request timeout to 1200s (20 minutes).
# A single stuck request — an xpath show that the device never answers, a
# half-open connection — therefore blocks for 20 minutes. Because the read
# tools call pan-os-python synchronously, that block freezes the whole MCP
# process (even local tools like server_status stop responding). We cap every
# request at a sane bound so a stuck call fails fast instead of hanging.
#
# This is a *per-request* timeout, not a per-operation one: commits and pushes
# submit a job then poll with many short requests, so each request stays well
# under the cap — bounding it here does not truncate a long commit.
_DEFAULT_API_TIMEOUT = 60


def _api_timeout() -> int:
    """Per-request API timeout in seconds (override via ``PANOS_API_TIMEOUT``)."""
    raw = os.environ.get("PANOS_API_TIMEOUT")
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return _DEFAULT_API_TIMEOUT


@dataclass(frozen=True)
class ResolveError:
    """Returned when a tool requested a target that can't be resolved.

    Tools surface ``ResolveError.message`` to the AI rather than raising,
    so the model gets a clean error string instead of a stack trace.
    """

    message: str


_CLIENTS: dict[str, Firewall | Panorama] = {}
"""Cache of constructed clients keyed by entry (or discovered device) name.

Lifetime = server process."""


@dataclass(frozen=True)
class DeviceInfo:
    """A device as reported by Panorama's ``show devices all``."""

    serial: str
    hostname: str
    connected: bool


_DEVICE_MAPS: dict[str, dict[str, DeviceInfo]] = {}
"""Cache of Panorama-managed device inventories, keyed by Panorama hostname.

Each value maps every device's hostname *and* serial to its :class:`DeviceInfo`
so a caller can target by either. Populated lazily on the first serial-proxy
resolution against a given Panorama; cleared by :func:`reset_client_cache`."""

# PAN-OS spells the connected flag a few ways across versions; treat any of
# these as "reachable".
_CONNECTED_TRUE = frozenset({"yes", "true", "1", "connected", "up"})


def _tls_kwargs(tls: TlsConfig) -> dict[str, Any]:
    """Build the ``verify`` kwarg for pan-os-python from our TLS config."""
    if not tls.verify:
        return {"verify": False}
    if tls.ca_path is not None and tls.ca_bundle is not None:
        return {"verify": str(tls.ca_path)}
    return {}


def _build_client(entry: FirewallEntry, tls: TlsConfig) -> Firewall | Panorama:
    """Construct the correct ``pan-os-python`` client for the entry.

    Probes the device with the **class-neutral** ``show system info`` to read
    its model, then constructs a ``Panorama`` when the model indicates a
    Panorama appliance (model == "Panorama" or starts with "M-") and a
    ``Firewall`` otherwise.  The detected type is cached for the server
    lifetime.

    The probe deliberately uses ``show_system_info()`` (which just returns the
    raw ``show system info`` dict) rather than the ``Firewall`` subclass's
    ``refresh_system_info()``.  ``Firewall._save_system_info`` parses
    firewall-only fields — ``app-version`` and ``multi-vsys`` — that a
    Panorama's ``show system info`` does **not** return, so calling it on a
    Panorama raised ``KeyError: 'multi-vsys'`` *before* the model could be
    inspected.  That exception was caught below and the appliance was silently
    cached as a ``Firewall``, which then failed every ``isinstance(client,
    Panorama)`` guard (redirect/reject guards, scope- and template-aware walks,
    serial-through-Panorama resolution) — producing misleading empty/zero
    results on a Panorama target.
    """
    base_kwargs: dict[str, Any] = {
        "hostname": entry.host,
        "api_key": entry.api_key,
        **_tls_kwargs(tls),
    }
    probe: Firewall | Panorama = Firewall(**base_kwargs)
    # Set the timeout BEFORE the first API call. pan-os-python builds the xapi
    # lazily from ``probe.timeout`` on first use and then caches it — setting
    # the attribute after the xapi exists does NOT propagate. show_system_info
    # below is the first call (and itself must not hang for 20 minutes when a
    # device is unreachable), so the cap has to be in place now.
    probe.timeout = _api_timeout()
    try:
        info = probe.show_system_info()
    except Exception as exc:
        # Render via redact_exception in case pan-python/requests leaked
        # the request URL (which carries ?key=<API_KEY>) into the message.
        print(
            f"[panos-mcp] WARNING: system-info probe failed for '{entry.name}' "
            f"({redact_exception(exc)}); treating as Firewall.",
            file=sys.stderr,
        )
        return probe

    system = info.get("system", {}) if isinstance(info, dict) else {}
    model = str(system.get("model") or "")
    version = str(system.get("sw-version") or "")

    if model == "Panorama" or model.startswith("M-"):
        client = Panorama(**base_kwargs)
        # Same ordering rule: set the cap before this client's xapi is built.
        client.timeout = _api_timeout()
        if version:
            client._set_version_and_version_info(version)
        print(
            f"[panos-mcp] Detected Panorama ({model}) for '{entry.name}'",
            file=sys.stderr,
        )
        return client

    # A real firewall: let the Firewall subclass fully populate itself
    # (version, serial, content_version, multi_vsys). Safe here — the firewall's
    # ``show system info`` carries the fields ``_save_system_info`` expects.
    try:
        probe.refresh_system_info()
    except Exception as exc:
        # Unexpected on a genuine firewall, but never let a parsing quirk drop
        # the working connection — fall back to the serial we already probed.
        print(
            f"[panos-mcp] WARNING: refresh_system_info failed for firewall "
            f"'{entry.name}' ({redact_exception(exc)}); using probed serial.",
            file=sys.stderr,
        )
        probe.serial = str(system.get("serial") or "") or probe.serial
    print(
        f"[panos-mcp] Detected Firewall ({model or 'unknown'}) for '{entry.name}'",
        file=sys.stderr,
    )
    return probe


def get_client(
    name: str | None,
    *,
    tls: TlsConfig,
) -> Firewall | Panorama | ResolveError:
    """Return a cached client for the named target.

    Resolution order:

    1. A **configured entry** (``firewalls.json`` or the ``PANOS_HOST`` env
       fallback) — direct connection, or a serial-proxy entry routed through
       Panorama.
    2. When ``PANOS_ALLOW_SERIAL_CONNECTION`` is enabled and ``name`` is not a
       configured entry, a **Panorama-managed device** discovered live via
       ``show devices all`` and reached through Panorama by serial.

    Direct/configured entries always win, so a device reachable both directly
    and through Panorama uses its direct connection. Returns :class:`ResolveError`
    instead of raising so tools can surface a clean message without try/except.
    """
    entry = resolve_firewall(name)
    if entry is not None:
        cached = _CLIENTS.get(entry.name)
        if cached is not None:
            return cached
        client = (
            _build_serial_client(entry, tls=tls) if entry.is_proxy else _build_client(entry, tls)
        )
        if isinstance(client, ResolveError):
            return client
        _CLIENTS[entry.name] = client
        return client

    if name is None:
        return ResolveError(
            "No firewall configured. Set PANOS_HOST/PANOS_API_KEY or "
            "create a firewalls.json with at least one entry."
        )

    # Not a configured entry — try dynamic discovery through Panorama.
    if serial_connection_enabled():
        cached = _CLIENTS.get(name)
        if cached is not None:
            return cached
        discovered = _discover_serial_client(name, tls=tls)
        if isinstance(discovered, ResolveError):
            return discovered
        _CLIENTS[name] = discovered
        return discovered

    return ResolveError(
        f"Firewall '{name}' not found. Use list_firewalls to see configured targets. "
        f"(Serial-through-Panorama is off — set {SERIAL_CONNECTION_ENV}=true to reach "
        "Panorama-managed devices by hostname or serial.)"
    )


def reset_client_cache() -> None:
    """Drop all cached clients and device maps. Used by tests; rarely needed at runtime."""
    _CLIENTS.clear()
    _DEVICE_MAPS.clear()


# --- Serial-through-Panorama resolution -------------------------------------


def _panorama_to_proxy_through(via: str | None, *, tls: TlsConfig) -> Panorama | ResolveError:
    """Resolve the Panorama a serial-proxy target should route through.

    ``via`` names a configured Panorama entry; ``None`` means the default
    connection (the single configured entry or the ``PANOS_HOST`` fallback).
    Errors cleanly when the target doesn't resolve or isn't a Panorama.
    """
    pano = get_client(via, tls=tls)
    if isinstance(pano, ResolveError):
        return pano
    if not isinstance(pano, Panorama):
        target = f"'{via}'" if via else "the default connection"
        return ResolveError(
            f"Serial-through-Panorama requires {target} to be a Panorama, but it "
            f"resolved to a {type(pano).__name__}. Point 'via' at a Panorama entry."
        )
    return pano


def _default_panorama(tls: TlsConfig) -> Panorama | None:
    """Find the Panorama to use for dynamic device discovery.

    Prefers the default connection; if that isn't a Panorama (e.g. multiple
    entries are configured, so there's no default), scans the configured
    entries for the first that resolves to a Panorama. Returns None when no
    Panorama is reachable.
    """
    default = _panorama_to_proxy_through(None, tls=tls)
    if isinstance(default, Panorama):
        return default
    for record in list_firewall_entries():
        candidate = get_client(record["name"], tls=tls)
        if isinstance(candidate, Panorama):
            return candidate
    return None


def _proxied_firewall(pano: Panorama, serial: str) -> Firewall:
    """Build a Firewall that routes its API calls through ``pano`` via ``serial``.

    pan-os-python's :meth:`Firewall.generate_xapi` detects that ``serial`` is
    set with no ``hostname`` and a Panorama parent, and connects to Panorama
    with the serial as the ``target`` of each request (firewall.py). The
    per-request timeout must be set before the xapi is built lazily — same
    ordering rule as :func:`_build_client`.
    """
    fw = Firewall(serial=serial)
    pano.add(fw)
    fw.timeout = _api_timeout()
    return fw


def _build_serial_client(entry: FirewallEntry, *, tls: TlsConfig) -> Firewall | ResolveError:
    """Construct a proxied client for a configured serial-proxy entry."""
    if not serial_connection_enabled():
        return ResolveError(
            f"Firewall '{entry.name}' is a serial-through-Panorama target, but that path "
            f"is disabled. Set {SERIAL_CONNECTION_ENV}=true to enable it."
        )
    if entry.via is not None and entry.via == entry.name:
        return ResolveError(f"Serial entry '{entry.name}' cannot route through itself (via).")
    pano = _panorama_to_proxy_through(entry.via, tls=tls)
    if isinstance(pano, ResolveError):
        return pano
    assert entry.serial is not None  # guaranteed by is_proxy
    return _proxied_firewall(pano, entry.serial)


def _discover_serial_client(name: str, *, tls: TlsConfig) -> Firewall | ResolveError:
    """Resolve an unconfigured name to a Panorama-managed device and proxy to it."""
    pano = _default_panorama(tls)
    if pano is None:
        return ResolveError(
            f"'{name}' is not a configured firewall and no Panorama connection is available "
            "to look it up. Configure a Panorama (PANOS_HOST/PANOS_API_KEY or a firewalls.json "
            "entry) to reach managed devices by serial."
        )
    try:
        devices = _device_map(pano)
    except Exception as exc:  # network/parse failure enumerating devices
        return ResolveError(
            f"Could not enumerate Panorama-managed devices to resolve '{name}': "
            f"{redact_exception(exc)}"
        )
    info = devices.get(name)
    if info is None:
        return ResolveError(
            f"'{name}' is not a configured firewall and was not found among Panorama's "
            "managed devices (matched by hostname or serial). Use "
            "panorama_get_managed_devices or list_firewalls to see reachable targets."
        )
    if not info.connected:
        return ResolveError(
            f"Device '{name}' (serial {info.serial}) is registered with Panorama but "
            "currently disconnected, so it can't be reached via serial redirect."
        )
    return _proxied_firewall(pano, info.serial)


def _device_map(pano: Panorama) -> dict[str, DeviceInfo]:
    """Return (and cache) the hostname/serial → device map for a Panorama."""
    key = pano.hostname or "<panorama>"
    cached = _DEVICE_MAPS.get(key)
    if cached is not None:
        return cached
    devices = _fetch_device_map(pano)
    _DEVICE_MAPS[key] = devices
    return devices


def _fetch_device_map(pano: Panorama) -> dict[str, DeviceInfo]:
    """Run ``show devices all`` against ``pano`` and build the device map.

    ``cmd_xml=False`` sends the command as verbatim XML. pan-os-python's
    ``op()`` defaults to ``cmd_xml=True``, which treats the argument as a
    CLI-style string and re-encodes it — passing an already-XML payload under
    that default makes PAN-OS reject the request ("Request is not a valid
    XML"). This mirrors ``op_to_dict``, which the ``panorama_*`` op tools use.
    """
    resp = pano.op("<show><devices><all></all></devices></show>", cmd_xml=False)
    devices: dict[str, DeviceInfo] = {}
    for raw in _iter_device_entries(resp):
        serial = str(raw.get("serial") or "").strip()
        if not serial:
            continue
        hostname = str(raw.get("hostname") or "").strip()
        connected = str(raw.get("connected") or "").strip().lower() in _CONNECTED_TRUE
        info = DeviceInfo(serial=serial, hostname=hostname or serial, connected=connected)
        devices[serial] = info
        if hostname:
            devices[hostname] = info
    return devices


def _iter_device_entries(resp: Any) -> Iterator[dict[str, str]]:
    """Yield per-device field dicts from a ``show devices all`` response.

    Handles both a real pan-os-python ``Element`` response and a pre-parsed
    dict (used by tests), so the map builder doesn't care which it gets.
    """
    if isinstance(resp, Element):
        result = resp.find("./result")
        root = result if result is not None else resp
        # Only device entries — the direct ``entry`` children of a ``devices``
        # element. A device entry itself nests ``vsys/entry`` (``vsys1``) and
        # ``plugin_versions/entry`` (``dlp``); a blanket ``.//entry`` scoops
        # those up as phantom "devices", polluting the inventory.
        for entry in root.findall(".//devices/entry"):
            rec: dict[str, str] = {child.tag: (child.text or "").strip() for child in entry}
            name_attr = entry.get("name")
            if name_attr and "serial" not in rec:
                rec["serial"] = name_attr
            yield rec
        return
    if isinstance(resp, dict):
        yield from _dig_device_entries(resp)


def _dig_device_entries(node: Any) -> Iterator[dict[str, str]]:
    """Yield device entries from a parsed ``show devices all`` dict.

    Scoped to a ``devices`` container's direct ``entry`` children so nested
    per-device entries (``vsys/entry``, ``plugin_versions/entry``) are not
    mistaken for managed devices — the dict analogue of the ``.//devices/entry``
    selector used for the Element response.
    """
    if isinstance(node, dict):
        devices = node.get("devices")
        if isinstance(devices, dict):
            entry = devices.get("entry")
            if isinstance(entry, list):
                yield from (e for e in entry if isinstance(e, dict))
            elif isinstance(entry, dict):
                yield entry
        for key, value in node.items():
            if key != "devices" and isinstance(value, (dict, list)):
                yield from _dig_device_entries(value)
    elif isinstance(node, list):
        for value in node:
            yield from _dig_device_entries(value)


def discover_managed_devices(*, tls: TlsConfig) -> list[dict[str, Any]]:
    """List Panorama-managed devices reachable via serial redirect.

    Returns an empty list when serial connections are disabled or no Panorama
    is reachable — callers (``list_firewalls``) treat that as "nothing to add".
    Each device appears once (deduplicated by serial).
    """
    if not serial_connection_enabled():
        return []
    pano = _default_panorama(tls)
    if pano is None:
        return []
    try:
        devices = _device_map(pano)
    except Exception:
        return []
    unique: dict[str, DeviceInfo] = {info.serial: info for info in devices.values()}
    return [
        {
            "name": info.hostname,
            "serial": info.serial,
            "connected": info.connected,
            "reachable_via": "panorama-serial",
        }
        for info in unique.values()
    ]


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
    "DeviceInfo",
    "ResolveError",
    "discover_managed_devices",
    "get_client",
    "probe_client",
    "reset_client_cache",
]
