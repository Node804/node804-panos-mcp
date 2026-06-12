"""Tests for panos_mcp.config.firewalls — registry, keyring, file perms."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

import panos_mcp.config.firewalls as fw_module
from panos_mcp.config.firewalls import (
    KEYRING_SERVICE,
    FirewallEntry,
    get_config_path,
    is_multi_firewall,
    list_firewall_entries,
    load_firewall_config,
    resolve_firewall,
    save_firewall_entry,
)


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Each test gets a fresh registry + isolated env vars."""
    monkeypatch.setenv("PANOS_FIREWALLS_CONFIG", str(tmp_path / "firewalls.json"))
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    fw_module._entries = []
    yield
    fw_module._entries = []


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Replace the keyring backend with an in-memory dict for predictable tests."""
    store: dict[str, str] = {}
    fake = MagicMock()

    def get_password(service: str, username: str) -> str | None:
        return store.get(f"{service}::{username}")

    def set_password(service: str, username: str, password: str) -> None:
        store[f"{service}::{username}"] = password

    fake.get_password = get_password
    fake.set_password = set_password
    monkeypatch.setattr(fw_module, "keyring", fake)
    return store


@pytest.fixture
def no_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force keyring backend unavailable (Linux headless scenario)."""
    monkeypatch.setattr(fw_module, "_keyring_available", lambda: False)


# --- Validation -------------------------------------------------------------


class TestFirewallEntryValidation:
    def test_normalizes_host_strips_https(self) -> None:
        e = FirewallEntry(name="fw", host="https://fw.example.com/", api_key="k")
        assert e.host == "fw.example.com"

    def test_normalizes_host_strips_http(self) -> None:
        e = FirewallEntry(name="fw", host="HTTP://fw.example.com", api_key="k")
        assert e.host == "fw.example.com"

    def test_rejects_empty_host_after_normalization(self) -> None:
        with pytest.raises(ValidationError):
            FirewallEntry(name="fw", host="https://", api_key="k")

    @pytest.mark.parametrize("bad_name", ["evil'/x", "name<tag>", "a/b", "tab\there"])
    def test_rejects_unsafe_names(self, bad_name: str) -> None:
        with pytest.raises(ValidationError):
            FirewallEntry(name=bad_name, host="x", api_key="k")

    def test_accepts_valid_charset(self) -> None:
        e = FirewallEntry(name="hq-fw_2.lab Site", host="x", api_key="k")
        assert e.name == "hq-fw_2.lab Site"

    def test_rejects_too_long_name(self) -> None:
        with pytest.raises(ValidationError):
            FirewallEntry(name="a" * 64, host="x", api_key="k")


# --- Loading + resolution ---------------------------------------------------


class TestLoadFirewallConfig:
    def test_no_file_yields_empty_registry(self) -> None:
        load_firewall_config()
        assert list_firewall_entries() == []

    def test_loads_entries_with_keyring_keys(self, fake_keyring: dict[str, str]) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [
            {"name": "fw1", "host": "10.0.0.1"},
            {"name": "fw2", "host": "10.0.0.2"},
        ]}))
        fake_keyring[f"{KEYRING_SERVICE}::fw1"] = "key-1"
        fake_keyring[f"{KEYRING_SERVICE}::fw2"] = "key-2"

        load_firewall_config()
        entries = list_firewall_entries()
        assert {e["name"] for e in entries} == {"fw1", "fw2"}
        assert is_multi_firewall() is True

    def test_skips_entries_with_no_key(
        self, fake_keyring: dict[str, str], capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [{"name": "fw1", "host": "10.0.0.1"}]}))
        # No keyring entry for fw1.
        load_firewall_config()
        assert list_firewall_entries() == []
        assert "no keychain entry for firewall 'fw1'" in capsys.readouterr().err


class TestPlaintextKeyMigration:
    def test_migrates_plaintext_to_keychain_and_rewrites_file(
        self, fake_keyring: dict[str, str], capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [
            {"name": "fw1", "host": "10.0.0.1", "api_key": "key-1"},
            {"name": "fw2", "host": "10.0.0.2", "api_key": "key-2"},
        ]}))

        load_firewall_config()

        # Keys moved to keyring
        assert fake_keyring[f"{KEYRING_SERVICE}::fw1"] == "key-1"
        assert fake_keyring[f"{KEYRING_SERVICE}::fw2"] == "key-2"
        # JSON re-written without api_key fields
        on_disk = json.loads(path.read_text())
        for entry in on_disk["firewalls"]:
            assert "api_key" not in entry
        # Stderr notice
        assert "Migrated 2 API key(s)" in capsys.readouterr().err
        # Registry resolved correctly
        e = resolve_firewall("fw1")
        assert e is not None
        assert e.api_key == "key-1"

    def test_keeps_plaintext_when_keychain_unavailable(self, no_keyring: None) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [
            {"name": "fw1", "host": "10.0.0.1", "api_key": "key-1"},
        ]}))
        load_firewall_config()
        e = resolve_firewall("fw1")
        assert e is not None
        assert e.api_key == "key-1"
        # File NOT rewritten (still has the plaintext key)
        assert "api_key" in path.read_text()


class TestResolveFirewall:
    def test_returns_none_when_unset(self) -> None:
        load_firewall_config()
        assert resolve_firewall() is None

    def test_falls_back_to_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_HOST", "10.0.0.1")
        monkeypatch.setenv("PANOS_API_KEY", "envkey")
        load_firewall_config()
        e = resolve_firewall()
        assert e is not None
        assert e.name == "env"
        assert e.host == "10.0.0.1"
        assert e.api_key == "envkey"

    def test_env_host_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANOS_HOST", "https://fw.example.com/")
        monkeypatch.setenv("PANOS_API_KEY", "x")
        load_firewall_config()
        e = resolve_firewall()
        assert e is not None
        assert e.host == "fw.example.com"

    def test_single_entry_resolves_without_name(self, fake_keyring: dict[str, str]) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [{"name": "fw1", "host": "10.0.0.1"}]}))
        fake_keyring[f"{KEYRING_SERVICE}::fw1"] = "k"
        load_firewall_config()
        e = resolve_firewall()
        assert e is not None
        assert e.name == "fw1"
        assert is_multi_firewall() is False

    def test_multi_entry_requires_explicit_name(self, fake_keyring: dict[str, str]) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [
            {"name": "fw1", "host": "10.0.0.1"},
            {"name": "fw2", "host": "10.0.0.2"},
        ]}))
        fake_keyring[f"{KEYRING_SERVICE}::fw1"] = "k1"
        fake_keyring[f"{KEYRING_SERVICE}::fw2"] = "k2"
        load_firewall_config()
        assert resolve_firewall() is None  # ambiguous
        assert resolve_firewall("fw1") is not None
        assert resolve_firewall("fw2") is not None
        assert resolve_firewall("fw3") is None  # not found

    def test_list_entries_never_returns_keys(self, fake_keyring: dict[str, str]) -> None:
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"firewalls": [{"name": "fw1", "host": "10.0.0.1"}]}))
        fake_keyring[f"{KEYRING_SERVICE}::fw1"] = "secret-key"
        load_firewall_config()
        for entry in list_firewall_entries():
            assert "api_key" not in entry
            assert "secret-key" not in str(entry)


# --- Save -------------------------------------------------------------------


class TestSaveFirewallEntry:
    def test_writes_to_keychain_and_file_without_keys(
        self, fake_keyring: dict[str, str]
    ) -> None:
        load_firewall_config()
        save_firewall_entry(
            FirewallEntry(name="new-fw", host="10.0.0.5", api_key="new-key")
        )
        # Key in keychain
        assert fake_keyring[f"{KEYRING_SERVICE}::new-fw"] == "new-key"
        # File stored without the key
        on_disk = json.loads(get_config_path().read_text())
        assert on_disk["firewalls"] == [{"name": "new-fw", "host": "10.0.0.5"}]
        # Resolves immediately
        e = resolve_firewall("new-fw")
        assert e is not None
        assert e.api_key == "new-key"

    def test_writes_plaintext_when_no_keychain(
        self, no_keyring: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_firewall_config()
        save_firewall_entry(
            FirewallEntry(name="new-fw", host="10.0.0.5", api_key="plain-key")
        )
        on_disk = json.loads(get_config_path().read_text())
        assert on_disk["firewalls"][0]["api_key"] == "plain-key"
        assert "keychain unavailable" in capsys.readouterr().err

    def test_updates_existing_entry_in_place(self, fake_keyring: dict[str, str]) -> None:
        load_firewall_config()
        save_firewall_entry(FirewallEntry(name="fw", host="10.0.0.1", api_key="v1"))
        save_firewall_entry(FirewallEntry(name="fw", host="10.0.0.2", api_key="v2"))
        on_disk = json.loads(get_config_path().read_text())
        assert len(on_disk["firewalls"]) == 1
        assert on_disk["firewalls"][0]["host"] == "10.0.0.2"
        e = resolve_firewall("fw")
        assert e is not None and e.api_key == "v2"

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows ACLs don't expose POSIX mode bits")
    def test_file_written_with_mode_0o600(self, fake_keyring: dict[str, str]) -> None:
        load_firewall_config()
        save_firewall_entry(FirewallEntry(name="fw", host="10.0.0.1", api_key="k"))
        st = os.stat(get_config_path())
        assert st.st_mode & 0o777 == 0o600
