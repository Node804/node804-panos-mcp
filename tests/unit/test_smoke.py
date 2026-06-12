"""Phase 0 smoke tests — confirm the package imports and the hello-world tool exists.

Real coverage starts in Phase 1 (toolkit) and Phase 3 (read tools). These tests
just prove the bootstrap is wired correctly.
"""

from panos_mcp import __version__
from panos_mcp.server import mcp, server_info


def test_version_is_set() -> None:
    assert __version__ == "0.1.0"


def test_server_info_returns_phase_marker() -> None:
    info = server_info()
    assert info["name"] == "panos-mcp"
    assert info["version"] == __version__
    assert "0 (bootstrap" in info["phase"]


def test_mcp_server_named_correctly() -> None:
    assert mcp.name == "panos-mcp"
