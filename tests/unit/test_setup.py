"""Tests for panos_mcp.setup — the install wizard (config building + wiring)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import panos_mcp.config.firewalls as fw_module
import panos_mcp.setup as wizard
from panos_mcp.setup import (
    build_server_entry,
    claude_config_path,
    main,
    upsert_claude_server,
)


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """In-memory keyring shared by both the setup and firewalls modules."""
    store: dict[str, str] = {}
    fake = MagicMock()
    fake.get_password = lambda service, user: store.get(f"{service}::{user}")
    fake.set_password = lambda service, user, pw: store.__setitem__(f"{service}::{user}", pw)
    fake.delete_password = lambda service, user: store.pop(f"{service}::{user}", None)
    monkeypatch.setattr(fw_module, "keyring", fake)
    monkeypatch.setattr(wizard, "keyring", fake)
    return store


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    monkeypatch.delenv("PANOS_SETUP_API_KEY", raising=False)
    fw_module._entries = []
    yield
    fw_module._entries = []


# --- build_server_entry -----------------------------------------------------


def test_server_entry_omits_host_and_key() -> None:
    entry = build_server_entry(
        python_exe=r"C:\Py\python.exe", mode="read", serial=False, tls_verify=True
    )
    assert entry["command"] == r"C:\Py\python.exe"
    assert entry["args"] == ["-m", "panos_mcp"]
    assert entry["env"] == {"PANOS_MODE": "read"}
    assert "PANOS_HOST" not in entry["env"]
    assert "PANOS_API_KEY" not in entry["env"]


def test_server_entry_optional_flags() -> None:
    entry = build_server_entry(
        python_exe="py", mode="full", serial=True, tls_verify=False, audit_log="/tmp/a.log"
    )
    assert entry["env"]["PANOS_MODE"] == "full"
    assert entry["env"]["PANOS_ALLOW_SERIAL_CONNECTION"] == "true"
    assert entry["env"]["PANOS_TLS_VERIFY"] == "false"
    assert entry["env"]["PANOS_AUDIT_LOG"] == "/tmp/a.log"


# --- claude_config_path -----------------------------------------------------


@pytest.mark.parametrize(
    "platform,needle",
    [("win32", "Claude"), ("darwin", "Application Support"), ("linux", ".config")],
)
def test_config_path_per_os(monkeypatch: pytest.MonkeyPatch, platform: str, needle: str) -> None:
    monkeypatch.setattr("sys.platform", platform)
    monkeypatch.setenv("APPDATA", r"C:\Users\x\AppData\Roaming")
    assert needle in str(claude_config_path())
    assert claude_config_path().name == "claude_desktop_config.json"


# --- upsert_claude_server ---------------------------------------------------


def test_upsert_creates_file(tmp_path: Path) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    backup = upsert_claude_server(cfg, "PAN-OS", {"command": "py", "args": [], "env": {}})
    assert backup is None
    data = json.loads(cfg.read_text())
    assert "PAN-OS" in data["mcpServers"]


def test_upsert_preserves_others_and_backs_up(tmp_path: Path) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}, "foo": 1}))
    backup = upsert_claude_server(cfg, "PAN-OS", {"command": "py"})
    assert backup is not None and backup.exists()
    data = json.loads(cfg.read_text())
    assert data["mcpServers"]["other"] == {"command": "x"}  # untouched
    assert data["mcpServers"]["PAN-OS"] == {"command": "py"}  # added
    assert data["foo"] == 1  # top-level keys preserved


def test_upsert_replaces_existing_entry(tmp_path: Path) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"mcpServers": {"PAN-OS": {"command": "old"}}}))
    upsert_claude_server(cfg, "PAN-OS", {"command": "new"})
    data = json.loads(cfg.read_text())
    assert data["mcpServers"]["PAN-OS"] == {"command": "new"}


# --- end-to-end (non-interactive) -------------------------------------------


def test_main_non_interactive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_keyring: dict[str, str]
) -> None:
    monkeypatch.setenv("PANOS_SETUP_API_KEY", "SECRETKEY123")
    cfg = tmp_path / "claude_desktop_config.json"
    rc = main(
        [
            "--name",
            "hq",
            "--host",
            "https://hq.example.com/",
            "--mode",
            "standard",
            "--yes",
            "--claude",
            "--serial",
            "--claude-config",
            str(cfg),
            "--no-skill",
        ]
    )
    assert rc == 0

    # Key went to the keychain, not to any file.
    assert fake_keyring["panos-mcp::hq"] == "SECRETKEY123"

    # firewalls.json holds name + normalized host, no key.
    fw = json.loads((tmp_path / "firewalls.json").read_text())
    assert fw["firewalls"][0]["name"] == "hq"
    assert fw["firewalls"][0]["host"] == "hq.example.com"
    assert "api_key" not in fw["firewalls"][0]

    # Claude entry has mode + serial, never the host or key.
    entry = json.loads(cfg.read_text())["mcpServers"]["PAN-OS"]
    assert entry["env"]["PANOS_MODE"] == "standard"
    assert entry["env"]["PANOS_ALLOW_SERIAL_CONNECTION"] == "true"
    assert "PANOS_HOST" not in entry["env"]
    assert "PANOS_API_KEY" not in entry["env"]


def test_main_rejects_bad_mode(fake_keyring: dict[str, str]) -> None:
    # argparse rejects an invalid --mode choice with SystemExit(2).
    with pytest.raises(SystemExit):
        main(
            ["--name", "hq", "--host", "h", "--mode", "bogus", "--yes", "--no-claude", "--no-skill"]
        )


def test_main_no_key_non_interactive_fails(tmp_path: Path, fake_keyring: dict[str, str]) -> None:
    rc = main(["--name", "hq", "--host", "h", "--yes", "--no-claude", "--no-skill"])
    assert rc == 2  # no PANOS_SETUP_API_KEY and no existing keychain entry


def test_main_installs_skill(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_keyring: dict[str, str]
) -> None:
    monkeypatch.setenv("PANOS_SETUP_API_KEY", "SECRETKEY123")
    monkeypatch.chdir(tmp_path)  # zip lands in cwd
    skills_dir = tmp_path / "skills"
    rc = main(
        [
            "--name",
            "hq",
            "--host",
            "hq.example.com",
            "--yes",
            "--no-claude",
            "--skill",
            "--skills-dir",
            str(skills_dir),
        ]
    )
    assert rc == 0
    # Skill folder copied for Claude Code, with its SKILL.md and references.
    installed = skills_dir / "panos-engineer"
    assert (installed / "SKILL.md").is_file()
    assert (installed / "references").is_dir()
    # Zip produced for Claude Desktop upload, containing the top-level folder.
    zip_path = tmp_path / "panos-engineer-skill.zip"
    assert zip_path.is_file()
    import zipfile

    names = zipfile.ZipFile(zip_path).namelist()
    assert any(n.startswith("panos-engineer/") and n.endswith("SKILL.md") for n in names)


# --- firewall subcommand ----------------------------------------------------


def _add_entry(monkeypatch: pytest.MonkeyPatch, name: str, host: str) -> None:
    monkeypatch.setenv("PANOS_SETUP_API_KEY", "K-" + name)
    assert main(["firewall", "add", "--name", name, "--host", host, "--yes"]) == 0
    monkeypatch.delenv("PANOS_SETUP_API_KEY", raising=False)


def test_firewall_add_list_remove(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_keyring: dict[str, str], capsys: Any
) -> None:
    _add_entry(monkeypatch, "hq", "hq.example.com")
    _add_entry(monkeypatch, "branch", "branch.example.com")
    assert fake_keyring["panos-mcp::hq"] == "K-hq"
    fw = json.loads((tmp_path / "firewalls.json").read_text())
    assert {e["name"] for e in fw["firewalls"]} == {"hq", "branch"}

    capsys.readouterr()
    assert main(["firewall", "list"]) == 0
    out = capsys.readouterr().out
    assert "hq" in out and "branch" in out

    assert main(["firewall", "remove", "--name", "hq"]) == 0
    fw = json.loads((tmp_path / "firewalls.json").read_text())
    assert {e["name"] for e in fw["firewalls"]} == {"branch"}
    assert "panos-mcp::hq" not in fake_keyring

    assert main(["firewall", "remove", "--name", "nope"]) == 1  # missing → non-zero


# --- skill subcommand -------------------------------------------------------


def test_skill_subcommand_installs_and_zips(tmp_path: Path, fake_keyring: dict[str, str]) -> None:
    skills_dir = tmp_path / "skills"
    rc = main(["skill", "--skills-dir", str(skills_dir), "--zip-dir", str(tmp_path)])
    assert rc == 0
    assert (skills_dir / "panos-engineer" / "SKILL.md").is_file()
    assert (tmp_path / "panos-engineer-skill.zip").is_file()


def test_skill_subcommand_no_zip(tmp_path: Path, fake_keyring: dict[str, str]) -> None:
    skills_dir = tmp_path / "skills"
    rc = main(["skill", "--skills-dir", str(skills_dir), "--zip-dir", str(tmp_path), "--no-zip"])
    assert rc == 0
    assert (skills_dir / "panos-engineer" / "SKILL.md").is_file()
    assert not (tmp_path / "panos-engineer-skill.zip").exists()


# --- modify-aware wizard ----------------------------------------------------


def test_wizard_skips_firewall_when_entry_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_keyring: dict[str, str]
) -> None:
    _add_entry(monkeypatch, "hq", "hq.example.com")
    # No --name and no key available: the wizard must NOT force a firewall
    # re-entry (defaults to "no") and should still succeed.
    rc = main(["--yes", "--no-claude", "--no-skill"])
    assert rc == 0
    fw = json.loads((tmp_path / "firewalls.json").read_text())
    assert [e["name"] for e in fw["firewalls"]] == ["hq"]  # unchanged
