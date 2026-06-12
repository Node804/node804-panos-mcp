"""Entry point for ``python -m panos_mcp``.

This file makes the package runnable as a module — useful when an MCP host
config prefers to specify a Python interpreter explicitly rather than rely
on the ``node804-panos-mcp`` console script being on the user's PATH.

Both invocations call the same ``main()`` function:

    node804-panos-mcp         # via [project.scripts] console script
    python -m panos_mcp       # via this file

Pick whichever is easier to configure in your MCP host.
"""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    main()
