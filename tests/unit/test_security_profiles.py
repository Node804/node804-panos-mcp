"""Tests for the security-profile aggregator.

Regression coverage for the import bug where ``_security_profile_objects``
tried to import ``AntiSpywareProfile`` & friends from ``panos.objects`` —
classes that pan-os-python does not define. The aggregator now reads the
``profiles`` config subtree via the XML API, so these tests drive it through
a fake client that returns that subtree.
"""

from __future__ import annotations

from typing import Any

from panos.panorama import Panorama

from panos_mcp.tools.security import _profiles_xpath, _security_profile_objects


class _FakeFirewall:
    """Minimal stand-in exposing the bits the aggregator touches."""

    vsys = None

    def __init__(self, profiles: dict[str, Any]) -> None:
        self._profiles = profiles

    def xpath_root(self, root: Any, vsys: str) -> str:
        return f"/config/devices/entry/vsys/entry[@name='{vsys}']"

    def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
        # op_to_dict passes a dict straight through; mirror the <result> body.
        return {"profiles": self._profiles}


def test_imports_do_not_blow_up() -> None:
    """The module imports cleanly — no top-level import of missing classes."""
    # Importing the symbols above already exercised this; assert they exist.
    assert callable(_security_profile_objects)
    assert callable(_profiles_xpath)


def test_firewall_xpath_targets_vsys() -> None:
    fw = _FakeFirewall({})
    assert _profiles_xpath(fw).endswith("/profiles")
    assert "vsys1" in _profiles_xpath(fw)


def test_panorama_xpath_is_shared() -> None:
    pano = Panorama("h", "u", "p")
    assert _profiles_xpath(pano) == "/config/shared/profiles"


def test_aggregates_multiple_types_and_normalizes_name() -> None:
    fw = _FakeFirewall(
        {
            "virus": {
                "entry": {"@_name": "av-default", "description": "default AV"}
            },
            "spyware": {
                "entry": [
                    {"@_name": "as-strict", "description": "strict"},
                    {"@_name": "as-loose"},
                ]
            },
        }
    )
    items = _security_profile_objects(fw)

    by_name = {i["name"]: i for i in items}
    assert by_name["av-default"]["type"] == "antivirus"
    assert by_name["av-default"]["description"] == "default AV"
    assert by_name["as-strict"]["type"] == "anti-spyware"
    # Single-entry nodes and multi-entry nodes both flatten; "@_name" is gone.
    assert "@_name" not in by_name["as-loose"]
    assert by_name["as-loose"]["name"] == "as-loose"
    assert len(items) == 3


def test_empty_profiles_returns_empty_list() -> None:
    assert _security_profile_objects(_FakeFirewall({})) == []


def test_missing_profiles_node_returns_empty_list() -> None:
    class NoProfiles(_FakeFirewall):
        def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
            return {}

    assert _security_profile_objects(NoProfiles({})) == []


def test_no_such_node_xapi_error_returns_empty_list() -> None:
    """When the queried xpath doesn't exist on the device — most commonly a
    Panorama with no profiles configured at the Shared scope — PAN-OS
    returns ``<response status="error"><msg>No such node</msg></response>``
    and pan-python raises ``PanXapiError``. That's the same semantic
    signal as an empty config subtree and must surface as an empty list,
    not a tool error that misleads the caller into thinking the call
    failed at the network layer.
    """
    from pan.xapi import PanXapiError

    class NoSuchNode(_FakeFirewall):
        def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
            raise PanXapiError("No such node")

    assert _security_profile_objects(NoSuchNode({})) == []


def test_unrelated_xapi_error_still_propagates() -> None:
    """The ``No such node`` swallow must be narrow — auth/network failures
    are real errors the caller has to see. Any other error message keeps
    propagating.
    """
    from pan.xapi import PanXapiError

    import pytest

    class AuthFailure(_FakeFirewall):
        def op(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
            raise PanXapiError("Invalid credentials")

    with pytest.raises(PanXapiError):
        _security_profile_objects(AuthFailure({}))
