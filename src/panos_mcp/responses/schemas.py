"""Per-tool LeanShape definitions.

One source of truth for which fields each read tool exposes by default
(``verbose=False``) versus all available fields (``verbose=True``). Keeping
them centralized makes the token-efficiency story auditable: anyone
reviewing this file can see exactly what's being sent to the AI by default.

Naming convention: ``SHAPE_<TOOL_NAME>``, in the order tools appear in
:mod:`panos_mcp.tools`.

For tools that return op-command output where field names are PAN-OS
short-form (``vsys-info``, ``av-version``, etc.), we still use lean
defaults — just pulling out the most frequently relevant fields.
"""

from __future__ import annotations

from .shapers import LeanShape

# --- System ---------------------------------------------------------------

SHAPE_FIREWALL_INFO = LeanShape(
    default_fields=(
        "hostname",
        "model",
        "serial",
        "sw-version",
        "ip-address",
        "uptime",
        "multi-vsys",
    ),
)
"""``get_firewall_info`` lean view. Verbose adds licensing, signatures, etc."""

SHAPE_HA_STATUS = LeanShape(
    default_fields=(
        "enabled",
        "state",
        "peer-info",
        "running-sync",
        "running-sync-enabled",
    ),
)

SHAPE_ACTIVE_SESSIONS = LeanShape(
    default_fields=(
        "num-active",
        "num-tcp",
        "num-udp",
        "num-icmp",
        "num-installed",
        "num-max",
        "cps",
        "kbps",
    ),
)

SHAPE_SYSTEM_RESOURCES = LeanShape(
    default_fields=("cpu", "memory", "load-average"),
)


# --- Network --------------------------------------------------------------

SHAPE_INTERFACE = LeanShape(
    default_fields=("name", "ip", "state", "zone", "vsys", "mac"),
)

SHAPE_ZONE = LeanShape(
    default_fields=("name", "network", "enable_user_identification"),
)

SHAPE_ROUTE = LeanShape(
    default_fields=("destination", "nexthop", "interface", "metric", "flags", "age"),
    name_field="destination",
)

SHAPE_ARP = LeanShape(
    default_fields=("ip", "mac", "interface", "ttl", "status"),
    name_field="ip",
)

SHAPE_VLAN = LeanShape(
    default_fields=("name", "interface", "virtual-interface"),
)

SHAPE_DHCP_LEASE = LeanShape(
    default_fields=("ip", "mac", "hostname", "state", "lease-time", "interface"),
    name_field="ip",
)

SHAPE_DNS_PROXY = LeanShape(
    default_fields=("name", "interface", "primary", "secondary", "domain"),
)

SHAPE_STATIC_ROUTE = LeanShape(
    default_fields=("name", "destination", "nexthop", "interface", "metric"),
)


# --- Security policy ------------------------------------------------------

SHAPE_SECURITY_RULE = LeanShape(
    default_fields=(
        "name",
        "fromzone",
        "tozone",
        "source",
        "destination",
        "application",
        "service",
        "action",
        "disabled",
        # Derived booleans added by ``enrich_security_rule_dicts``. They answer
        # the two most common audit questions ("is a profile attached?",
        # "is logging forwarded?") without forcing the caller to fetch
        # ``profile_setting`` / ``group`` / ``log_setting`` per rule.
        "has_inspection",
        "has_log_setting",
    ),
)
"""Verbose adds the raw fields ``has_inspection`` / ``has_log_setting`` are
derived from — ``group``, the individual profile fields (``virus``,
``spyware``, ``vulnerability``, ``url_filtering``, ``file_blocking``,
``data_filtering``, ``wildfire_analysis``), ``log_setting`` — plus
``log_start``, ``log_end``, ``tag``, ``uuid``, audit comments, and the rest
of ``.about()``."""

SHAPE_PROFILE = LeanShape(
    default_fields=("name", "description"),
)

SHAPE_PROFILE_GROUP = LeanShape(
    default_fields=(
        "name",
        "virus",
        "spyware",
        "vulnerability",
        "url_filtering",
        "file_blocking",
        "wildfire_analysis",
    ),
)

SHAPE_PBF_RULE = LeanShape(
    default_fields=("name", "fromzone", "source", "action", "disabled"),
)

SHAPE_DOS_PROFILE = LeanShape(
    default_fields=("name", "type", "description"),
)

SHAPE_QOS_RULE = LeanShape(
    default_fields=(
        "name",
        "fromzone",
        "tozone",
        "source",
        "destination",
        "action_class",
        "disabled",
    ),
)


# --- Objects -------------------------------------------------------------

SHAPE_ADDRESS_OBJECT = LeanShape(
    default_fields=("name", "ip_netmask", "ip_range", "fqdn", "description", "tag"),
)

SHAPE_ADDRESS_GROUP = LeanShape(
    default_fields=("name", "static_value", "dynamic_value", "description", "tag"),
)

SHAPE_SERVICE_OBJECT = LeanShape(
    default_fields=("name", "protocol", "source_port", "destination_port", "description"),
)

SHAPE_SERVICE_GROUP = LeanShape(
    default_fields=("name", "value", "tag"),
)

SHAPE_APPLICATION_FILTER = LeanShape(
    default_fields=("name", "category", "subcategory", "technology", "risk", "tag"),
)

SHAPE_TAG = LeanShape(
    default_fields=("name", "color", "comments"),
)


# --- NAT ----------------------------------------------------------------

SHAPE_NAT_RULE = LeanShape(
    default_fields=(
        "name",
        "fromzone",
        "tozone",
        "source",
        "destination",
        "service",
        "source_translation_type",
        "source_translation_address",
        "destination_translated_address",
        "destination_translated_port",
        "disabled",
    ),
)


# --- User-ID ------------------------------------------------------------

SHAPE_USERID_MAPPING = LeanShape(
    default_fields=("ip", "user", "type", "vsys", "idle-timeout", "max-timeout"),
    name_field="user",
)

SHAPE_USERID_GROUP = LeanShape(
    default_fields=("name", "members"),
)

SHAPE_USERID_AGENT = LeanShape(
    default_fields=("name", "host", "port", "enabled", "ldap_proxy"),
)


# --- Admin --------------------------------------------------------------

SHAPE_ADMIN = LeanShape(
    default_fields=("name", "authentication_profile", "permissions", "role"),
)

SHAPE_ADMIN_ROLE = LeanShape(
    default_fields=("name", "role"),
)

SHAPE_AUTH_PROFILE = LeanShape(
    default_fields=("name", "method", "server_profile", "lockout"),
)


# --- VPN ---------------------------------------------------------------

SHAPE_IPSEC_TUNNEL = LeanShape(
    default_fields=("name", "state", "peer-ip", "interface", "tunnel-id"),
)

SHAPE_GP_USER = LeanShape(
    default_fields=(
        "user",
        "domain",
        "computer",
        "primary-username",
        "vpn-type",
        "client",
        "login-time",
    ),
    name_field="user",
)

SHAPE_GP_CONFIG = LeanShape(
    default_fields=("name", "portal_address", "gateway_address", "tunnel_interface"),
)


# --- Logs --------------------------------------------------------------

SHAPE_TRAFFIC_LOG = LeanShape(
    default_fields=(
        "receive_time",
        "src",
        "dst",
        "rule",
        "app",
        "action",
        "bytes",
        "packets",
        "session_end_reason",
    ),
    name_field="receive_time",
)

SHAPE_THREAT_LOG = LeanShape(
    default_fields=(
        "receive_time",
        "src",
        "dst",
        "rule",
        "threat_name",
        "severity",
        "action",
        "category",
    ),
    name_field="threat_name",
)

SHAPE_SYSTEM_LOG = LeanShape(
    default_fields=("receive_time", "severity", "subtype", "event_id", "description"),
    name_field="event_id",
)

SHAPE_CONFIG_LOG = LeanShape(
    default_fields=("receive_time", "admin", "client", "result", "cmd", "path"),
    name_field="cmd",
)

SHAPE_URL_LOG = LeanShape(
    default_fields=(
        "receive_time",
        "src",
        "dst",
        "rule",
        "url",
        "category",
        "action",
        "user",
    ),
    name_field="url",
)


# --- Threat / Content --------------------------------------------------

SHAPE_WILDFIRE = LeanShape(
    default_fields=("status", "registration", "subscription", "license-expired"),
)

SHAPE_AV_VERSION = LeanShape(
    default_fields=(
        "av-version",
        "av-release-date",
        "threat-version",
        "threat-release-date",
        "wildfire-version",
        "wildfire-release-date",
    ),
)

SHAPE_CONTENT_VERSIONS = LeanShape(
    default_fields=("version", "filename", "released-on", "downloaded", "current", "size"),
    name_field="version",
)

SHAPE_URL_CATEGORY = LeanShape(
    default_fields=("name", "description"),
)


# --- Certificates / Decryption ---------------------------------------

SHAPE_CERTIFICATE = LeanShape(
    default_fields=("name", "subject", "issuer", "expiry-epoch", "expiry-date", "common-name"),
)

SHAPE_DECRYPTION_RULE = LeanShape(
    default_fields=(
        "name",
        "fromzone",
        "tozone",
        "source",
        "destination",
        "service",
        "action",
        "type",
        "disabled",
    ),
)

SHAPE_DECRYPTION_PROFILE = LeanShape(
    default_fields=("name", "description"),
)


# --- Licenses --------------------------------------------------------

# authcode is a reusable activation credential — kept out of the lean default
# so it isn't handed to the LLM (or any transcript log) unless explicitly
# requested via verbose=true or fields=["authcode"].
SHAPE_LICENSE = LeanShape(
    default_fields=("feature", "description", "expires", "issued"),
    name_field="feature",
)

SHAPE_LICENSE_USAGE = LeanShape(
    default_fields=("model", "serial", "vm-license", "vm-mode", "vm-capacity-tier"),
)


# --- Panorama -------------------------------------------------------

SHAPE_MANAGED_DEVICE = LeanShape(
    default_fields=("serial", "hostname", "ip-address", "model", "sw-version", "connected"),
    name_field="hostname",
)

SHAPE_DEVICE_GROUP = LeanShape(
    default_fields=("name", "description", "parent_dg", "devices"),
)

SHAPE_TEMPLATE = LeanShape(
    default_fields=("name", "description", "default_vsys"),
)

SHAPE_TEMPLATE_STACK = LeanShape(
    default_fields=("name", "description", "templates", "devices"),
)

SHAPE_LOG_COLLECTOR = LeanShape(
    default_fields=("serial", "hostname", "connected", "sw-version"),
    name_field="hostname",
)

SHAPE_COLLECTOR_GROUP = LeanShape(
    default_fields=("name", "description", "log-collectors"),
)

SHAPE_PUSH_STATUS = LeanShape(
    default_fields=("id", "type", "status", "result", "tfin", "user", "devices"),
    name_field="id",
)

SHAPE_COMMIT_JOB = LeanShape(
    default_fields=("id", "type", "status", "result", "tfin", "user"),
    name_field="id",
)


# --- Utility -----------------------------------------------------

SHAPE_CONFIG_XPATH = LeanShape(
    # Raw XPath reads return arbitrary structure; the lean view just drops
    # PAN-OS internal attribute prefixes that are noise for the AI.
    extra_strip_keys=("@_uuid", "@_dirtyId", "@_loc", "@_overrides"),
)


__all__ = [name for name in dir() if name.startswith("SHAPE_")]
