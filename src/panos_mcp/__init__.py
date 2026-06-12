"""Token-efficient MCP server for Palo Alto Networks PAN-OS firewalls and Panorama.

Greenfield Python rebuild of the TypeScript fork at ../Palo-MCP/, designed around
lean responses, default-deny RBAC, and aggregation tools that replace dump-and-filter
patterns. See plan in C:/Users/mpope/.claude/plans/purring-fluttering-giraffe.md.
"""

__version__ = "0.1.0"
