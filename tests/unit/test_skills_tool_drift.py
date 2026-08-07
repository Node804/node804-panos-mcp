"""Skills must reference only tools the server actually registers.

Skills in ``skills/`` name the tools they drive as ``mcp__panos__<tool>``. A tool
rename or removal would silently rot those playbooks — the agent would try to
call a tool that no longer exists. This test scans every skill markdown file for
``mcp__panos__*`` references and asserts each resolves to a registered tool, so
drift fails CI instead of surfacing at runtime on a live firewall.
"""

from __future__ import annotations

import re
from pathlib import Path

import panos_mcp.server as server

_SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
_TOOL_REF = re.compile(r"mcp__panos__([a-z0-9_]+)")


def _registered_tool_names() -> set[str]:
    """Every tool the server registers at import time (short, unprefixed names)."""
    tools = server.mcp._tool_manager._tools  # type: ignore[attr-defined]
    return set(tools or {})


def _skill_files() -> list[Path]:
    if not _SKILLS_DIR.is_dir():
        return []
    return sorted(_SKILLS_DIR.rglob("*.md"))


def test_skills_directory_is_present() -> None:
    # Guards against the test silently passing because the tree moved/renamed.
    assert _SKILLS_DIR.is_dir(), f"skills directory not found at {_SKILLS_DIR}"
    assert _skill_files(), "no skill markdown files found under skills/"


def test_every_skill_tool_reference_is_registered() -> None:
    registered = _registered_tool_names()
    assert registered, "server registered no tools — import/setup problem"

    unknown: dict[str, set[str]] = {}
    for path in _skill_files():
        refs = set(_TOOL_REF.findall(path.read_text(encoding="utf-8")))
        missing = refs - registered
        if missing:
            rel = path.relative_to(_SKILLS_DIR.parent)
            unknown[str(rel)] = missing

    assert not unknown, (
        f"skill files reference tools that are not registered (renamed or removed?): {unknown}"
    )
