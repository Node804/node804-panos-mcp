"""Interactive setup wizard for panos-mcp.

Run it after ``pip install node804-panos-mcp`` (or ``uvx``):

    node804-panos-mcp-setup          # console script
    python -m panos_mcp.setup        # equivalent

It walks through the things the server needs:

1. a ``firewalls.json`` entry (name + host) at the standard config location;
2. the API key, stored in the OS keychain (Windows Credential Manager, macOS
   Keychain, Linux Secret Service) — never written to disk in plaintext;
3. a server entry in your Claude Desktop config, pointing at this interpreter,
   with no host or key in the config (both come from 1 and 2); and
4. the ``panos-engineer`` skill — copied into ``~/.claude/skills`` for Claude
   Code, and zipped for upload to Claude Desktop / claude.ai.

Nothing sensitive is echoed: the key is read with ``getpass`` and handed
straight to the keychain. The Claude Desktop config is backed up before it is
touched.

Subcommands (the wizard is the default when none is given)::

    node804-panos-mcp-setup                 # full wizard (modify-aware)
    node804-panos-mcp-setup skill           # install/upgrade the skill only
    node804-panos-mcp-setup firewall list   # show configured entries
    node804-panos-mcp-setup firewall add    # add or update an entry
    node804-panos-mcp-setup firewall remove --name hq

The wizard is modify-aware: when ``firewalls.json`` already has entries it lists
them and lets you skip straight to the client/skill steps, so re-running it to
re-wire a client or refresh the skill does not force you to re-enter a firewall.

Non-interactive use (for scripted installs): pass ``--name`` / ``--host`` /
``--mode`` and provide the key in the ``PANOS_SETUP_API_KEY`` environment
variable. Add ``--yes`` to accept every default without prompting.
"""

from __future__ import annotations

import argparse
import getpass
import importlib.resources as ir
import json
import os
import shutil
import sys
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import keyring

from .config.firewalls import (
    KEYRING_SERVICE,
    FirewallEntry,
    get_config_path,
    list_firewall_entries,
    load_firewall_config,
    remove_firewall_entry,
    save_firewall_entry,
)

MODES = ("read", "standard", "full", "admin")
DEFAULT_SERVER_NAME = "PAN-OS"
SKILL_NAME = "panos-engineer"


# --- Skill install ----------------------------------------------------------


def skill_source_dir() -> Path | None:
    """Locate the bundled ``panos-engineer`` skill folder.

    Prefers the copy shipped inside the installed wheel
    (``panos_mcp/skills/panos-engineer``); falls back to the repo-root
    ``skills/panos-engineer`` tree when running from a source checkout.
    """
    try:
        packaged = ir.files("panos_mcp") / "skills" / SKILL_NAME
        if packaged.is_dir():
            return Path(str(packaged))
    except (ModuleNotFoundError, AttributeError, TypeError):
        pass
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "skills" / SKILL_NAME
        if candidate.is_dir():
            return candidate
    return None


def claude_code_skills_dir() -> Path:
    """Personal Claude Code skills directory (``~/.claude/skills``)."""
    return Path.home() / ".claude" / "skills"


def install_skill_to_dir(skills_dir: Path) -> Path:
    """Copy the bundled skill folder into ``skills_dir`` (overwriting an old copy).

    Returns the destination skill path. Raises ``FileNotFoundError`` when the
    bundled skill can't be located.
    """
    src = skill_source_dir()
    if src is None:
        raise FileNotFoundError("bundled panos-engineer skill not found")
    dest = skills_dir / SKILL_NAME
    skills_dir.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    return dest


def zip_skill(dest_zip: Path) -> Path:
    """Write a ``panos-engineer`` skill zip for Claude Desktop / claude.ai upload.

    The archive contains a top-level ``panos-engineer/`` folder (what the Skills
    uploader expects). Returns the zip path.
    """
    src = skill_source_dir()
    if src is None:
        raise FileNotFoundError("bundled panos-engineer skill not found")
    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                zf.write(path, Path(SKILL_NAME) / path.relative_to(src))
    return dest_zip


# --- Claude Desktop config --------------------------------------------------


def claude_config_path() -> Path:
    """Return the Claude Desktop config path for this OS.

    Windows: ``%APPDATA%\\Claude``; macOS: ``~/Library/Application Support/Claude``;
    otherwise ``~/.config/Claude`` (best effort).
    """
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def build_server_entry(
    *,
    python_exe: str,
    mode: str,
    serial: bool,
    tls_verify: bool,
    audit_log: str | None = None,
) -> dict[str, Any]:
    """Build a Claude Desktop ``mcpServers`` entry for panos-mcp.

    Deliberately omits ``PANOS_HOST`` and ``PANOS_API_KEY`` — the host comes
    from ``firewalls.json`` and the key from the keychain, so neither lands in
    the Claude config.
    """
    env: dict[str, str] = {"PANOS_MODE": mode}
    if serial:
        env["PANOS_ALLOW_SERIAL_CONNECTION"] = "true"
    if not tls_verify:
        env["PANOS_TLS_VERIFY"] = "false"
    if audit_log:
        env["PANOS_AUDIT_LOG"] = audit_log
    return {"command": python_exe, "args": ["-m", "panos_mcp"], "env": env}


def upsert_claude_server(
    config_path: Path,
    server_name: str,
    entry: dict[str, Any],
    *,
    backup: bool = True,
) -> Path | None:
    """Add or replace ``server_name`` under ``mcpServers`` in the Claude config.

    Creates the file if missing. Backs up an existing file (timestamped) before
    writing and returns the backup path, or ``None`` when no backup was made.
    Other servers and top-level keys are preserved.
    """
    backup_path: Path | None = None
    if config_path.exists():
        if backup:
            backup_path = config_path.with_suffix(f".json.bak.{time.strftime('%Y%m%d-%H%M%S')}")
            shutil.copy2(config_path, backup_path)
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError(f"{config_path} is not a JSON object")
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = {}

    servers = config.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("'mcpServers' in the config is not a JSON object")
    servers[server_name] = entry

    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return backup_path


# --- Agent registry ---------------------------------------------------------
# One entry == one question in the wizard. To support another client later,
# write a ``_configure_<agent>`` function and append an AgentSetup here.


@dataclass(frozen=True)
class AgentSetup:
    """A configurable AI client the wizard can wire up to the server."""

    key: str
    label: str
    configure: Callable[[argparse.Namespace, str], None]
    flag_attr: str | None = None  # args attribute that forces on/off (None → prompt)


def _configure_claude_desktop(args: argparse.Namespace, mode: str) -> None:
    serial = args.serial
    if serial is None:
        serial = _prompt_yes_no(
            "Is this a Panorama you reach managed firewalls through (serial routing)?",
            False,
            assume_yes=args.yes,
        )
    entry = build_server_entry(
        python_exe=sys.executable,
        mode=mode,
        serial=serial,
        tls_verify=not args.no_tls_verify,
        audit_log=args.audit_log,
    )
    cfg_path = Path(args.claude_config) if args.claude_config else claude_config_path()
    backup = upsert_claude_server(cfg_path, args.server_name, entry)
    print(f"[ok] Updated Claude Desktop config: {cfg_path}")
    if backup:
        print(f"     (backup saved: {backup.name})")
    print("\nServer entry written (host + key resolved from firewalls.json + keychain):")
    print("  " + json.dumps({args.server_name: entry}, indent=2).replace("\n", "\n  "))
    print("Next: fully quit Claude Desktop (including the tray/menu-bar icon) and reopen it.")


AGENT_SETUPS: list[AgentSetup] = [
    AgentSetup(
        key="claude-desktop",
        label="Claude Desktop",
        configure=_configure_claude_desktop,
        flag_attr="claude",
    ),
]


# --- Prompt helpers ---------------------------------------------------------


def _prompt(label: str, default: str | None, *, assume_yes: bool) -> str:
    """Prompt for a value, returning ``default`` when the user just hits Enter."""
    suffix = f" [{default}]" if default is not None else ""
    if assume_yes and default is not None:
        print(f"{label}{suffix}: {default}")
        return default
    while True:
        raw = input(f"{label}{suffix}: ").strip()
        if raw:
            return raw
        if default is not None:
            return default
        print("  A value is required.")


def _prompt_yes_no(label: str, default: bool, *, assume_yes: bool) -> bool:
    d = "Y/n" if default else "y/N"
    if assume_yes:
        print(f"{label} [{d}]: {'yes' if default else 'no'}")
        return default
    raw = input(f"{label} [{d}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


# --- Wizard -----------------------------------------------------------------


def _resolve_api_key(name: str, *, assume_yes: bool) -> str | None:
    """Get the API key for ``name``: env var, a kept keychain entry, or prompt."""
    existing = keyring.get_password(KEYRING_SERVICE, name)
    api_key: str | None = os.environ.get("PANOS_SETUP_API_KEY") or None
    if (
        api_key is None
        and existing
        and _prompt_yes_no(
            f"A key for '{name}' is already in the keychain. Keep it?",
            True,
            assume_yes=assume_yes,
        )
    ):
        api_key = existing
    if api_key is None and not assume_yes:
        api_key = getpass.getpass(f"PAN-OS API key for '{name}' (input hidden): ").strip()
    return api_key or None


def _save_firewall(name: str, host: str, *, assume_yes: bool) -> int:
    """Store the key in the keychain and add/update the firewalls.json entry."""
    api_key = _resolve_api_key(name, assume_yes=assume_yes)
    if not api_key:
        print(
            "ERROR: no API key. Set PANOS_SETUP_API_KEY for non-interactive use, "
            "or run interactively.",
            file=sys.stderr,
        )
        return 2
    save_firewall_entry(FirewallEntry(name=name, host=host, api_key=api_key))
    print(f"[ok] Stored key in keychain (service '{KEYRING_SERVICE}', entry '{name}').")
    print(f"[ok] Updated {get_config_path()} (name + host; no key).")
    return 0


def _print_entries(entries: list[dict[str, str]]) -> None:
    for e in entries:
        target = e.get("host") or e.get("serial") or "?"
        print(f"  - {e['name']}  ({target})")


def _do_skill_install(
    *, skills_dir: Path, do_copy: bool = True, do_zip: bool = True, zip_dir: Path | None = None
) -> int:
    """Install/upgrade the skill: copy into ``skills_dir`` and/or write an upload zip."""
    if skill_source_dir() is None:
        print("[warn] bundled panos-engineer skill not found; nothing to install.", file=sys.stderr)
        return 1
    if do_copy:
        dest = install_skill_to_dir(skills_dir)
        print(f"[ok] Installed/updated skill for Claude Code: {dest}")
    if do_zip:
        zip_path = (zip_dir or Path.cwd()) / f"{SKILL_NAME}-skill.zip"
        zip_skill(zip_path)
        print(f"[ok] Wrote {zip_path}")
        print(
            "     For Claude Desktop / claude.ai, upload that zip under "
            "Settings → Capabilities → Skills."
        )
    return 0


# --- Wizard -----------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    print("panos-mcp setup\n" + "=" * 15)

    load_firewall_config()
    existing = list_firewall_entries()
    if existing:
        print(f"\nExisting entries in {get_config_path()}:")
        _print_entries(existing)

    # Add/update a firewall entry. Forced when --name/--host are given or nothing
    # is configured yet; otherwise opt-in, so a re-run can go straight to the
    # client/skill steps without re-entering the firewall.
    if args.name or args.host:
        do_fw = True
    elif existing:
        do_fw = _prompt_yes_no("\nAdd or update a firewall entry?", False, assume_yes=args.yes)
    else:
        do_fw = True

    if do_fw:
        name = args.name or _prompt("Firewall / Panorama name", "panorama", assume_yes=args.yes)
        host = args.host or _prompt(
            "Hostname (e.g. panorama.example.com)", None, assume_yes=args.yes
        )
        rc = _save_firewall(name, host, assume_yes=args.yes)
        if rc:
            return rc

    mode = args.mode or _prompt(
        "Permission mode (read/standard/full/admin)", "read", assume_yes=args.yes
    )
    if mode not in MODES:
        print(f"ERROR: mode must be one of {', '.join(MODES)}.", file=sys.stderr)
        return 2

    # --- AI agents ----------------------------------------------------------
    # Each agent is one question. Add a new AgentSetup to AGENT_SETUPS to offer
    # another client (Codex, Cursor, ...) — the loop below picks it up.
    for agent in AGENT_SETUPS:
        forced = getattr(args, agent.flag_attr) if agent.flag_attr else None
        want = (
            forced
            if forced is not None
            else _prompt_yes_no(f"Set up {agent.label}?", True, assume_yes=args.yes)
        )
        if want:
            agent.configure(args, mode)

    # --- panos-engineer skill ----------------------------------------------
    want_skill = args.skill
    if want_skill is None:
        want_skill = _prompt_yes_no(
            "\nInstall the panos-engineer skill?", True, assume_yes=args.yes
        )
    if want_skill:
        skills_dir = Path(args.skills_dir) if args.skills_dir else claude_code_skills_dir()
        _do_skill_install(skills_dir=skills_dir)

    print('\nVerify in your client by asking: "What\'s my access level?"')
    return 0


def run_firewall(args: argparse.Namespace) -> int:
    """``firewall`` subcommand: list / add / remove entries in firewalls.json."""
    load_firewall_config()
    cmd = args.fw_command or "list"

    if cmd == "list":
        entries = list_firewall_entries()
        if not entries:
            print(f"No entries in {get_config_path()}.")
            return 0
        print(f"Entries in {get_config_path()}:")
        _print_entries(entries)
        return 0

    if cmd == "add":
        name = args.name or _prompt("Firewall / Panorama name", "panorama", assume_yes=args.yes)
        host = args.host or _prompt(
            "Hostname (e.g. panorama.example.com)", None, assume_yes=args.yes
        )
        return _save_firewall(name, host, assume_yes=args.yes)

    if cmd == "remove":
        if remove_firewall_entry(args.name):
            print(f"[ok] Removed '{args.name}' from {get_config_path()} and the keychain.")
            return 0
        print(f"[warn] No entry named '{args.name}'.", file=sys.stderr)
        return 1

    return 2


def run_skill(args: argparse.Namespace) -> int:
    """``skill`` subcommand: install or upgrade the panos-engineer skill."""
    skills_dir = Path(args.skills_dir) if args.skills_dir else claude_code_skills_dir()
    zip_dir = Path(args.zip_dir) if args.zip_dir else None
    return _do_skill_install(
        skills_dir=skills_dir,
        do_copy=not args.no_copy,
        do_zip=not args.no_zip,
        zip_dir=zip_dir,
    )


def _add_wizard_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--name", help="Firewall / Panorama entry name (keychain username).")
    p.add_argument("--host", help="Firewall or Panorama hostname.")
    p.add_argument("--mode", choices=MODES, help="Permission mode (default: read).")
    p.add_argument(
        "--server-name",
        default=DEFAULT_SERVER_NAME,
        help=f"Name of the server entry in the Claude config (default: {DEFAULT_SERVER_NAME}).",
    )
    p.add_argument("--audit-log", help="Path for PANOS_AUDIT_LOG (optional).")
    p.add_argument("--claude-config", help="Override the Claude Desktop config path.")
    p.add_argument(
        "--no-tls-verify",
        action="store_true",
        help="Set PANOS_TLS_VERIFY=false (self-signed cert; prefer PANOS_TLS_CA instead).",
    )
    claude = p.add_mutually_exclusive_group()
    claude.add_argument(
        "--claude",
        dest="claude",
        action="store_true",
        default=None,
        help="Configure Claude Desktop without prompting.",
    )
    claude.add_argument(
        "--no-claude", dest="claude", action="store_false", help="Skip the Claude Desktop step."
    )
    serial = p.add_mutually_exclusive_group()
    serial.add_argument(
        "--serial",
        dest="serial",
        action="store_true",
        default=None,
        help="Enable PANOS_ALLOW_SERIAL_CONNECTION (reach managed firewalls through Panorama).",
    )
    serial.add_argument(
        "--no-serial",
        dest="serial",
        action="store_false",
        help="Do not enable serial-through-Panorama routing.",
    )
    skill = p.add_mutually_exclusive_group()
    skill.add_argument(
        "--skill",
        dest="skill",
        action="store_true",
        default=None,
        help="Install the panos-engineer skill without prompting.",
    )
    skill.add_argument(
        "--no-skill",
        dest="skill",
        action="store_false",
        help="Skip installing the panos-engineer skill.",
    )
    p.add_argument(
        "--skills-dir",
        help="Override the Claude Code skills directory (default: ~/.claude/skills).",
    )
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Accept defaults without prompting (key must come from PANOS_SETUP_API_KEY).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="node804-panos-mcp-setup",
        description=(
            "Set up and manage panos-mcp: firewalls.json, the keychain key, "
            "AI-client config, and the panos-engineer skill."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    _add_wizard_args(sub.add_parser("wizard", help="Full interactive setup (default)."))

    sk = sub.add_parser("skill", help="Install or upgrade the panos-engineer skill only.")
    sk.add_argument(
        "--skills-dir", help="Claude Code skills directory (default: ~/.claude/skills)."
    )
    sk.add_argument("--zip-dir", help="Directory for the Desktop upload zip (default: cwd).")
    sk.add_argument("--no-copy", action="store_true", help="Do not copy into the skills directory.")
    sk.add_argument("--no-zip", action="store_true", help="Do not write the Desktop upload zip.")

    fw = sub.add_parser("firewall", help="Manage firewalls.json entries.")
    fwsub = fw.add_subparsers(dest="fw_command")
    fwsub.add_parser("list", help="List configured entries.")
    fw_add = fwsub.add_parser("add", help="Add or update an entry (key stored in the keychain).")
    fw_add.add_argument("--name", help="Entry name (keychain username).")
    fw_add.add_argument("--host", help="Firewall or Panorama hostname.")
    fw_add.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Non-interactive; key must come from PANOS_SETUP_API_KEY.",
    )
    fw_rm = fwsub.add_parser("remove", help="Remove an entry and its keychain key.")
    fw_rm.add_argument("--name", required=True, help="Entry name to remove.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()

    # Default to the wizard when no subcommand is given, so a bare
    # `node804-panos-mcp-setup` and `... --name x` both run the wizard — but let
    # top-level `-h/--help` through so the subcommands stay discoverable.
    raw = list(sys.argv[1:] if argv is None else argv)
    known = {"wizard", "skill", "firewall"}
    if raw and raw[0] not in known and raw[0] not in ("-h", "--help"):
        raw = ["wizard", *raw]
    elif not raw:
        raw = ["wizard"]
    args = parser.parse_args(raw)

    try:
        if args.command == "skill":
            return run_skill(args)
        if args.command == "firewall":
            return run_firewall(args)
        return run(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
