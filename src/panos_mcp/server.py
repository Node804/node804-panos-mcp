"""FastMCP server entrypoint.

Phase 0 (current): hello-world skeleton that proves the server boots, registers
a tool, and responds to MCP protocol over stdio. The RBAC gate, audit wrap,
and pan-os-python client come online in Phases 2+.
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from . import __version__

mcp = FastMCP("panos-mcp")


@mcp.tool()
def server_info() -> dict[str, str]:
    """Return server name, version, and bootstrap status. Phase 0 placeholder.

    Replaced in Phase 2 by a richer ``server_status`` tool that reports the
    active RBAC mode, TLS posture, audit destination, and configured firewalls.
    """
    return {
        "name": "panos-mcp",
        "version": __version__,
        "phase": "0 (bootstrap — hello world only)",
    }


def main() -> None:
    """Entry point for the ``panos-mcp`` console script."""
    print(f"panos-mcp {__version__} starting (phase 0)", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
