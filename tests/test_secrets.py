"""Tests for credential resolution (no plaintext in inventory)."""

from __future__ import annotations

from pathlib import Path

import pytest

from netaudit.models import Device
from netaudit.secrets import (
    SecretError,
    load_env_file,
    resolve_device_secrets,
    resolve_inventory_secrets,
    resolve_secret,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for key in list(os_environ_keys()):
        monkeypatch.delenv(key, raising=False)
    yield


def os_environ_keys() -> list[str]:
    import os

    return [k for k in os.environ if k.startswith(("NETAUDIT_", "FG_", "SCALANCE_", "CORE_SW_"))]


def _device(**kwargs) -> Device:
    base = {"name": "fg-120g-01", "host": "192.0.2.10", "platform": "fortigate", "username": "admin"}
    base.update(kwargs)
    return Device(**base)


def test_env_reference(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FG_PW", "s3cret")
    assert resolve_secret("env:FG_PW") == ("s3cret", "env")
    assert resolve_secret("${FG_PW}") == ("s3cret", "env")


def test_env_reference_missing():
    with pytest.raises(SecretError, match="not set"):
        resolve_secret("env:DOES_NOT_EXIST_12345")


def test_file_reference(tmp_path: Path):
    secret_file = tmp_path / "fg.txt"
    secret_file.write_text("from-file\nignored second line\n", encoding="utf-8")
    value, source = resolve_secret(f"file:{secret_file}")
    assert value == "from-file"
    assert source == "file"


def test_file_reference_missing(tmp_path: Path):
    with pytest.raises(SecretError, match="not found"):
        resolve_secret(f"file:{tmp_path / 'nope.txt'}")


def test_prompt_blocked_when_non_interactive():
    with pytest.raises(SecretError, match="non-interactive"):
        resolve_secret("prompt", allow_prompt=False)


def test_inline_password_is_flagged():
    device = _device(password="hardcoded123")
    resolved, statuses = resolve_device_secrets(device)
    assert resolved.password == "hardcoded123"
    password_status = next(s for s in statuses if s.field == "password")
    assert password_status.source == "inline"
    assert password_status.inline_plaintext is True


def test_env_reference_resolves_device(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FG_120G_01_PASSWORD", "vault-value")
    device = _device(password="env:FG_120G_01_PASSWORD")
    resolved, statuses = resolve_device_secrets(device)
    assert resolved.password == "vault-value"
    password_status = next(s for s in statuses if s.field == "password")
    assert password_status.source == "env"
    assert password_status.resolved is True


def test_auto_env_fallback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NETAUDIT_FG_120G_01_PASSWORD", "auto")
    device = _device(password="")
    resolved, statuses = resolve_device_secrets(device)
    assert resolved.password == "auto"
    assert next(s for s in statuses if s.field == "password").source == "auto-env"


def test_missing_password_is_unresolved():
    device = _device(password="env:NOT_SET_ANYWHERE_98765")
    resolved, statuses = resolve_device_secrets(device)
    assert resolved.password == ""
    password_status = next(s for s in statuses if s.field == "password")
    assert password_status.resolved is False
    assert password_status.source == "missing"


def test_optional_enable_password_absent_is_ok():
    device = _device(password="env:X", enable_password="")
    _resolved, statuses = resolve_device_secrets(device)
    enable_status = next(s for s in statuses if s.field == "enable_password")
    assert enable_status.resolved is True
    assert enable_status.source == "unset"


def test_status_never_holds_the_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FG_120G_01_PASSWORD", "super-secret-value")
    device = _device(password="env:FG_120G_01_PASSWORD")
    _resolved, statuses = resolve_device_secrets(device)
    assert "super-secret-value" not in repr(statuses)


def test_load_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "# comment line",
                "",
                'FG_120G_01_PASSWORD="quoted value"',
                "export SCALANCE_XC208_01_PASSWORD=plain",
                "MALFORMED_LINE",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("FG_120G_01_PASSWORD", raising=False)
    loaded = load_env_file(env)
    assert loaded["FG_120G_01_PASSWORD"] == "quoted value"
    assert loaded["SCALANCE_XC208_01_PASSWORD"] == "plain"
    assert "MALFORMED_LINE" not in loaded

    import os

    assert os.environ["FG_120G_01_PASSWORD"] == "quoted value"


def test_load_env_file_does_not_override_real_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FG_120G_01_PASSWORD", "from-shell")
    env = tmp_path / ".env"
    env.write_text("FG_120G_01_PASSWORD=from-dotenv\n", encoding="utf-8")
    load_env_file(env)

    import os

    assert os.environ["FG_120G_01_PASSWORD"] == "from-shell"


def test_load_env_file_missing_is_noop(tmp_path: Path):
    assert load_env_file(tmp_path / "absent.env") == {}


def test_resolve_inventory_secrets(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FG_120G_01_PASSWORD", "a")
    devices = [
        _device(password="env:FG_120G_01_PASSWORD"),
        _device(name="scalance-xc208-01", password="env:MISSING_54321"),
    ]
    resolved, statuses = resolve_inventory_secrets(devices)
    assert resolved[0].password == "a"
    assert resolved[1].password == ""
    assert len([s for s in statuses if not s.resolved]) == 1
