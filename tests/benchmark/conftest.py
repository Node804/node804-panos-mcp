"""Shared fixtures for the benchmark suite.

Each scenario gets a fixed-size synthetic policy/inventory so token counts
are reproducible across runs. The fixtures generate ``.about()`` dicts
identical in shape to what pan-os-python returns, so the same response
shapers run unmodified.

Run the suite with::

    pytest -v -m benchmark

The token counter uses tiktoken's ``cl100k_base`` encoding (GPT-4 / Claude
approximation). Absolute counts on a real Claude transcript will differ by
a few percent; what matters is the relative comparison between lean and
verbose responses, which the encoding captures accurately.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import tiktoken


@pytest.fixture(scope="session")
def tokenizer() -> tiktoken.Encoding:
    """The encoding used for all benchmark assertions."""
    return tiktoken.get_encoding("cl100k_base")


def count_tokens(tokenizer: tiktoken.Encoding, value: Any) -> int:
    """Token count of ``value`` after JSON-serialization (no whitespace).

    The MCP transport sends compact JSON, so we measure compact JSON.
    """
    serialized = json.dumps(value, separators=(",", ":"))
    return len(tokenizer.encode(serialized))


# ---------------------------------------------------------------------------
# Synthetic policy / inventory fixtures
# ---------------------------------------------------------------------------


def _security_rule(i: int) -> dict[str, Any]:
    """A realistic security rule .about() dict. ~50 fields, ~250 tokens raw."""
    return {
        "name": f"rule-{i:03d}",
        "uuid": f"01234567-89ab-cdef-{i:04d}-0123456789ab",
        "fromzone": ["trust"] if i % 2 == 0 else ["dmz"],
        "tozone": ["untrust"],
        "source": ["any"] if i % 5 == 0 else [f"src-net-{i % 10}"],
        "destination": ["any"] if i % 7 == 0 else [f"dst-host-{i % 20}"],
        "source_user": ["any"],
        "hip_profiles": ["any"],
        "application": [
            "web-browsing",
            "ssl",
            "social-networking",
        ] if i % 3 == 0 else ["application-default"],
        "service": ["application-default"],
        "category": ["any"],
        "action": "allow" if i % 4 != 0 else "deny",
        "log_setting": "panorama-forward",
        "log_start": False,
        "log_end": True,
        "description": (
            f"Rule {i} controls traffic between trust and untrust zones. "
            "Approved by SecOps on 2024-08-15 under ticket TKT-12345."
        ),
        "tag": ["compliance", f"v{i // 10}", "audited"],
        "group_tag": "social-controls",
        "negate_source": False,
        "negate_destination": False,
        "disabled": i % 30 == 0,
        "schedule": None,
        "icmp_unreachable": False,
        "type": "universal",
        "group": "strict" if i % 6 == 0 else None,
        "profile_setting": {"group": ["default"]} if i % 6 != 0 else None,
        "qos_marking": None,
        "qos_marking_dscp": None,
        "qos_marking_ip_precedence": None,
        "disable_server_response_inspection": False,
        "negate_target": False,
        "target": None,
    }


def _address_object(i: int) -> dict[str, Any]:
    """An address object .about() dict."""
    if i % 10 == 0:
        return {
            "name": f"fqdn-host-{i:03d}",
            "fqdn": f"host-{i}.example.com",
            "ip_netmask": None,
            "ip_range": None,
            "ip_wildcard": None,
            "description": f"FQDN object {i}",
            "tag": ["compliance"],
        }
    if i % 15 == 0:
        return {
            "name": f"range-{i:03d}",
            "ip_netmask": None,
            "ip_range": f"10.{i % 256}.0.1-10.{i % 256}.0.10",
            "fqdn": None,
            "ip_wildcard": None,
            "description": f"Range object {i}",
            "tag": None,
        }
    return {
        "name": f"net-{i:03d}",
        "ip_netmask": f"10.{i % 256}.0.0/24",
        "ip_range": None,
        "fqdn": None,
        "ip_wildcard": None,
        "description": f"Subnet object {i} — internal network segment",
        "tag": ["internal", f"segment-{i // 20}"],
    }


def _traffic_log_entry(i: int) -> dict[str, Any]:
    """A traffic log entry as PAN-OS returns it. ~80 fields, ~400 tokens raw."""
    return {
        "receive_time": f"2026/05/07 12:{(i % 60):02d}:{(i * 7 % 60):02d}",
        "serial": "001122334455",
        "type": "TRAFFIC",
        "subtype": "end",
        "config_ver": "2049",
        "time_generated": f"2026/05/07 12:{(i % 60):02d}:{(i * 7 % 60):02d}",
        "src": f"10.0.{i % 256}.{(i * 3) % 256}",
        "dst": f"203.0.113.{(i * 11) % 256}",
        "natsrc": "203.0.113.5",
        "natdst": f"203.0.113.{(i * 11) % 256}",
        "rule": f"rule-{i % 100:03d}",
        "src_user": f"user{i % 50}@example.local",
        "dst_user": "",
        "app": "web-browsing" if i % 2 == 0 else "ssl",
        "vsys": "vsys1",
        "from_zone": "trust",
        "to_zone": "untrust",
        "inbound_if": f"ethernet1/{i % 8 + 1}",
        "outbound_if": "ethernet1/2",
        "log_action": "panorama-forward",
        "time_logged": f"2026/05/07 12:{(i % 60):02d}:{(i * 7 % 60):02d}",
        "session_id": str(1000000 + i),
        "repeatcnt": 1,
        "sport": 49000 + (i % 1000),
        "dport": 443 if i % 2 != 0 else 80,
        "natsport": 33000 + (i % 1000),
        "natdport": 443 if i % 2 != 0 else 80,
        "flags": 0x100,
        "proto": "tcp",
        "action": "allow",
        "bytes": 1024 * (i + 1),
        "bytes_sent": 256 * (i + 1),
        "bytes_received": 768 * (i + 1),
        "packets": 10 + i,
        "start": f"2026/05/07 12:{(i % 60):02d}:00",
        "elapsed": 30 + (i % 90),
        "category": "computer-and-internet-info",
        "padding": 0,
        "seqno": 1000 + i,
        "actionflags": 0x8000000000000000,
        "src_country": "US",
        "dst_country": "US",
        "pkts_sent": 5 + i,
        "pkts_received": 5 + i,
        "session_end_reason": "tcp-fin",
        "device_name": "fw-hq",
        "action_source": "from-policy",
        "src_uuid": "",
        "dst_uuid": "",
        "tunnelid_imsi": 0,
        "monitortag_imei": "",
        "parent_session_id": 0,
        "parent_start_time": "",
        "tunnel": "N/A",
        "assoc_id": 0,
        "chunks": 1,
        "chunks_sent": 0,
        "chunks_received": 0,
        "rule_uuid": f"01234567-89ab-cdef-{i:04d}-0123456789ab",
        "http2_connection": 0,
        "link_change_count": 0,
        "policy_id": "01010101-2020-3030-4040-505050505050",
        "link_switches": "",
        "sdwan_cluster": "",
        "sdwan_device_type": "",
        "sdwan_cluster_type": "",
        "sdwan_site": "",
        "dynusergroup_name": "",
        "xff_ip": "",
        "src_category": "",
        "src_profile": "",
        "src_model": "",
        "src_vendor": "",
        "src_osfamily": "",
        "src_osversion": "",
        "src_host": "",
        "src_mac": "",
        "dst_category": "",
        "dst_profile": "",
        "dst_model": "",
        "dst_vendor": "",
        "dst_osfamily": "",
        "dst_osversion": "",
        "dst_host": "",
        "dst_mac": "",
    }


# ---------------------------------------------------------------------------
# Fixture sets (sized for realistic mid-size deployments)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def policy_100() -> list[dict[str, Any]]:
    """100 synthetic security rules."""
    return [_security_rule(i) for i in range(100)]


@pytest.fixture(scope="session")
def addresses_500() -> list[dict[str, Any]]:
    """500 synthetic address objects across types."""
    return [_address_object(i) for i in range(500)]


@pytest.fixture(scope="session")
def traffic_logs_50() -> list[dict[str, Any]]:
    """50 synthetic traffic log entries."""
    return [_traffic_log_entry(i) for i in range(50)]
