"""Smoke tests — confirm the package imports and the server module wires up.

Real coverage lives in test_firewalls, test_client, test_tools (Phase 2)
and the per-module suites added in later phases.
"""

from __future__ import annotations

import re

from panos_mcp import __version__


def test_version_is_set() -> None:
    # Match a semver-ish string rather than a literal so routine version
    # bumps don't break the smoke test.
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-].+)?", __version__), __version__


def test_server_module_imports() -> None:
    """The server module wires gate, audit, tls, and registers the always-on tools.

    Importing the module triggers all of that as side effects. If any wiring
    breaks, the import itself will fail with a clear traceback.
    """
    from panos_mcp.server import audit_sink, gate, mcp, tls_config

    assert mcp.name == "panos-mcp"
    assert gate.env_var == "PANOS_MODE"
    assert audit_sink is not None
    assert tls_config is not None

    # The two always-on tools should be in the gate's enabled set.
    enabled = gate.summary()["enabled_tools"]
    assert "server_status" in enabled
    assert "list_firewalls" in enabled
