"""Tests for dry-run, retry logic, and failure alerting."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netaudit import runner as runner_mod
from netaudit.models import Device
from netaudit.runner import AlertSink, backup_with_retry, dry_run, run_backups
from netaudit.ssh_backup import SSHBackupError
from netaudit.store import ConfigStore

CONFIG_A = "config system global\n    set hostname \"fg-120g-01\"\nend\n"
CONFIG_B = CONFIG_A + "config log syslogd setting\n    set status enable\nend\n"


def _device(name: str = "fg-120g-01", **kwargs) -> Device:
    base = {
        "name": name,
        "host": "127.0.0.1",
        "platform": "fortigate",
        "username": "admin",
        "password": "env:TEST_PW",
    }
    base.update(kwargs)
    return Device(**base)


@pytest.fixture
def env_password(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TEST_PW", "unit-test-password")
    return "unit-test-password"


def test_dry_run_flags_missing_credentials(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("TEST_PW", raising=False)
    report, statuses = dry_run([_device()], probe=False)
    assert report.mode == "dry-run"
    assert report.fail_count == 1
    assert report.results[0].status == "blocked"
    assert any(not s.resolved for s in statuses)


def test_dry_run_ready_when_probe_disabled(env_password: str):
    report, _statuses = dry_run([_device()], probe=False)
    assert report.fail_count == 0
    assert report.results[0].status == "ready"


def test_dry_run_probe_reports_unreachable(env_password: str):
    # port 1 on localhost is closed, so the probe fails fast
    report, _statuses = dry_run([_device(port=1)], probe=True, probe_timeout=2.0)
    assert report.results[0].status == "blocked"
    assert "unreachable" in (report.results[0].error or "")


def test_dry_run_writes_nothing(tmp_path: Path, env_password: str):
    store = ConfigStore(tmp_path / "backups")
    dry_run([_device()], probe=False)
    assert store.list_backups() == []


def test_backup_retries_then_succeeds(
    tmp_path: Path, env_password: str, monkeypatch: pytest.MonkeyPatch
):
    calls = {"n": 0}

    def flaky(device, timeout=None, progress=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise SSHBackupError("connection reset")
        return CONFIG_A

    monkeypatch.setattr(runner_mod, "backup_device", flaky)
    store = ConfigStore(tmp_path / "backups")

    result = backup_with_retry(_device(), store, retries=2, retry_delay=0)
    assert result.status == "ok"
    assert result.attempts == 3
    assert calls["n"] == 3
    assert len(store.list_backups("fg-120g-01")) == 1


def test_backup_gives_up_after_retries(
    tmp_path: Path, env_password: str, monkeypatch: pytest.MonkeyPatch
):
    def always_fails(device, timeout=None, progress=None):
        raise SSHBackupError("auth failed")

    monkeypatch.setattr(runner_mod, "backup_device", always_fails)
    store = ConfigStore(tmp_path / "backups")

    result = backup_with_retry(_device(), store, retries=2, retry_delay=0)
    assert result.status == "failed"
    assert result.attempts == 3
    assert "auth failed" in (result.error or "")


def test_backup_blocked_without_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("TEST_PW", raising=False)
    called = {"n": 0}

    def should_not_run(device, timeout=None, progress=None):
        called["n"] += 1
        return CONFIG_A

    monkeypatch.setattr(runner_mod, "backup_device", should_not_run)
    store = ConfigStore(tmp_path / "backups")

    result = backup_with_retry(_device(), store, retries=1, retry_delay=0)
    assert result.status == "blocked"
    assert called["n"] == 0


def test_unchanged_config_is_not_reported_as_change(
    tmp_path: Path, env_password: str, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(runner_mod, "backup_device", lambda *a, **k: CONFIG_A)
    store = ConfigStore(tmp_path / "backups")

    first = backup_with_retry(_device(), store, retries=0, retry_delay=0)
    second = backup_with_retry(_device(), store, retries=0, retry_delay=0)
    assert first.status == "ok"
    assert first.changed is True
    assert second.status == "unchanged"
    assert second.changed is False


def test_run_backups_alerts_on_failure(
    tmp_path: Path, env_password: str, monkeypatch: pytest.MonkeyPatch
):
    def fail_scalance(device, timeout=None, progress=None):
        if device.name == "scalance-xc208-01":
            raise SSHBackupError("timed out waiting for config output")
        return CONFIG_A

    monkeypatch.setattr(runner_mod, "backup_device", fail_scalance)
    store = ConfigStore(tmp_path / "backups")
    alert_file = tmp_path / "wazuh-netaudit.json"

    report = run_backups(
        [_device(), _device("scalance-xc208-01", platform="scalance_xc")],
        store,
        retries=0,
        retry_delay=0,
        alerts=AlertSink(wazuh_file=str(alert_file)),
    )

    assert report.fail_count == 1
    assert report.ok_count == 1
    assert report.alerts_sent

    events = [json.loads(line) for line in alert_file.read_text(encoding="utf-8").splitlines()]
    types = [e["netaudit"]["event_type"] for e in events]
    assert "backup_failed" in types
    assert "config_changed" in types
    assert "run_summary" in types

    failure = next(e for e in events if e["netaudit"]["event_type"] == "backup_failed")
    assert failure["netaudit"]["device"] == "scalance-xc208-01"
    assert failure["netaudit"]["severity"] == "high"
    assert failure["netaudit"]["wazuh_level"] == 10

    summary = next(e for e in events if e["netaudit"]["event_type"] == "run_summary")
    assert summary["netaudit"]["failed"] == 1
    assert summary["netaudit"]["severity"] == "high"


def test_run_backups_clean_run_summary_is_informational(
    tmp_path: Path, env_password: str, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(runner_mod, "backup_device", lambda *a, **k: CONFIG_A)
    store = ConfigStore(tmp_path / "backups")
    alert_file = tmp_path / "alerts.json"

    report = run_backups(
        [_device()], store, retries=0, retry_delay=0, alerts=AlertSink(wazuh_file=str(alert_file))
    )
    assert report.fail_count == 0

    events = [json.loads(line) for line in alert_file.read_text(encoding="utf-8").splitlines()]
    summary = next(e for e in events if e["netaudit"]["event_type"] == "run_summary")
    assert summary["netaudit"]["severity"] == "info"


def test_run_report_json_shape(tmp_path: Path, env_password: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(runner_mod, "backup_device", lambda *a, **k: CONFIG_B)
    store = ConfigStore(tmp_path / "backups")

    report = run_backups([_device()], store, retries=0, retry_delay=0)
    payload = report.to_dict()
    assert payload["mode"] == "backup"
    assert payload["devices"] == 1
    assert payload["ok"] == 1
    assert payload["results"][0]["device"] == "fg-120g-01"
    assert payload["started_at"] and payload["finished_at"]


def test_alert_sink_disabled_by_default():
    assert AlertSink().enabled is False
    assert AlertSink(wazuh_file="x.json").enabled is True
