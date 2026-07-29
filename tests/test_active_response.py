"""Alert-triggered backup (netaudit respond) and the Wazuh AR script."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from netaudit import runner as runner_mod
from netaudit.models import Device
from netaudit.runner import AlertSink, respond_to_alert
from netaudit.ssh_backup import SSHBackupError
from netaudit.store import ConfigStore

REPO = Path(__file__).resolve().parent.parent
AR_SCRIPT = REPO / "integrations" / "wazuh" / "active-response" / "netaudit-ar.py"
SAMPLES = REPO / "samples"

CONFIG_V1 = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")
CONFIG_V2 = CONFIG_V1.replace('set service "ALL"', 'set service "HTTPS"') + (
    "config system ntp\n    set ntpsync enable\nend\n"
)


@pytest.fixture
def device_password(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("TEST_PW", "unit-test-password")
    return "unit-test-password"


def _device() -> Device:
    return Device(
        name="fg-120g-01",
        host="127.0.0.1",
        username="admin",
        password="env:TEST_PW",
        platform="fortigate",
    )


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _payloads(path: Path) -> dict[str, dict]:
    return {e["netaudit"]["event_type"]: e["netaudit"] for e in _events(path)}


def test_respond_reports_change_with_diff(
    tmp_path: Path, device_password: str, monkeypatch: pytest.MonkeyPatch
):
    store = ConfigStore(tmp_path / "backups")
    store.save("fg-120g-01", CONFIG_V1)
    alert_file = tmp_path / "events.json"

    monkeypatch.setattr(
        runner_mod, "backup_device", lambda device, **kwargs: CONFIG_V2
    )

    report = respond_to_alert(
        _device(),
        store,
        triggered_by="wazuh rule 100580",
        agent="fw-edge",
        retries=0,
        alerts=AlertSink(wazuh_file=str(alert_file)),
    )

    assert report.status == "changed"
    assert report.changed
    assert report.added and report.removed
    assert "```diff" in report.diff_markdown
    assert report.findings > 0

    payloads = _payloads(alert_file)
    change = payloads["config_changed"]
    assert change["triggered_by"] == "wazuh rule 100580"
    assert change["agent"] == "fw-edge"
    assert change["added_lines"] == report.added
    assert any("ntpsync" in line for line in change["added_sample"])

    summary = payloads["respond_summary"]
    assert summary["changed"] is True
    assert summary["findings_total"] == report.findings
    assert summary["severity"] == "medium"


def test_respond_on_unchanged_config_is_quiet(
    tmp_path: Path, device_password: str, monkeypatch: pytest.MonkeyPatch
):
    store = ConfigStore(tmp_path / "backups")
    store.save("fg-120g-01", CONFIG_V1)
    alert_file = tmp_path / "events.json"

    monkeypatch.setattr(
        runner_mod, "backup_device", lambda device, **kwargs: CONFIG_V1
    )

    report = respond_to_alert(
        _device(),
        store,
        triggered_by="manual",
        retries=0,
        alerts=AlertSink(wazuh_file=str(alert_file)),
    )

    assert report.status == "unchanged"
    assert not report.changed
    assert report.added == report.removed == 0

    payloads = _payloads(alert_file)
    assert "config_changed" not in payloads
    assert payloads["respond_summary"]["severity"] == "info"
    # the audit still runs, so the insecure sample is still reported
    assert payloads["respond_summary"]["findings_serious"] >= 1


def test_respond_alerts_when_the_device_cannot_be_reached(
    tmp_path: Path, device_password: str, monkeypatch: pytest.MonkeyPatch
):
    store = ConfigStore(tmp_path / "backups")
    alert_file = tmp_path / "events.json"

    def unreachable(device, **kwargs):
        raise SSHBackupError("timed out waiting for config output")

    monkeypatch.setattr(runner_mod, "backup_device", unreachable)

    report = respond_to_alert(
        _device(),
        store,
        triggered_by="wazuh rule 100582",
        retries=0,
        retry_delay=0,
        alerts=AlertSink(wazuh_file=str(alert_file)),
    )

    assert report.failed
    assert report.status == "failed"
    assert "timed out" in report.error

    failure = _payloads(alert_file)["respond_failed"]
    assert failure["severity"] == "high"
    assert failure["triggered_by"] == "wazuh rule 100582"
    assert failure["wazuh_level"] == 10


def test_respond_report_json_is_serialisable(
    tmp_path: Path, device_password: str, monkeypatch: pytest.MonkeyPatch
):
    store = ConfigStore(tmp_path / "backups")
    monkeypatch.setattr(
        runner_mod, "backup_device", lambda device, **kwargs: CONFIG_V1
    )
    report = respond_to_alert(_device(), store, retries=0)

    data = json.loads(json.dumps(report.to_dict()))
    assert data["device"] == "fg-120g-01"
    assert "diff_markdown" not in data
    assert "events" not in data


def _load_ar_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("netaudit_ar", AR_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["netaudit_ar"] = module
    spec.loader.exec_module(module)
    return module


def test_ar_script_resolves_device_from_mapping(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "NETAUDIT_DEVICE_MAP", json.dumps({"fw-edge": "fg-120g-01", "10.0.0.5": "core-sw-01"})
    )
    ar = _load_ar_script()
    mapping = ar.device_map()

    alert = {"agent": {"name": "fw-edge", "ip": "10.0.0.9"}, "data": {}}
    assert ar.resolve_device(alert, mapping) == "fg-120g-01"

    by_ip = {"agent": {"name": "unknown-agent"}, "data": {"srcip": "10.0.0.5"}}
    assert ar.resolve_device(by_ip, mapping) == "core-sw-01"


def test_ar_script_prefers_the_device_named_in_the_alert(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NETAUDIT_DEVICE_MAP", raising=False)
    ar = _load_ar_script()

    fortios_alert = {"agent": {"name": "wazuh-manager"}, "data": {"devname": "fg-120g-01"}}
    assert ar.resolve_device(fortios_alert, {}) == "fg-120g-01"

    netaudit_alert = {"data": {"netaudit": {"device": "scalance-xc208-01"}}}
    assert ar.resolve_device(netaudit_alert, {}) == "scalance-xc208-01"

    assert ar.resolve_device({}, {}) is None


def test_ar_script_bad_device_map_is_ignored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("NETAUDIT_DEVICE_MAP", "{not json")
    monkeypatch.setenv("NETAUDIT_AR_LOG", str(tmp_path / "ar.log"))
    ar = _load_ar_script()
    assert ar.device_map() == {}
    assert "not valid JSON" in (tmp_path / "ar.log").read_text(encoding="utf-8")


def test_ar_script_trigger_label_includes_rule_id():
    ar = _load_ar_script()
    label = ar.trigger_label({"rule": {"id": "100580", "description": "FortiGate config changed"}})
    assert label == "wazuh rule 100580: FortiGate config changed"


def test_ar_script_main_invokes_netaudit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("NETAUDIT_AR_LOG", str(tmp_path / "ar.log"))
    monkeypatch.setenv("NETAUDIT_DEVICE_MAP", json.dumps({"fw-edge": "fg-120g-01"}))
    ar = _load_ar_script()

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(ar, "run_netaudit", lambda d, r, a: calls.append((d, r, a)) or 3)
    message = {
        "version": 1,
        "command": "add",
        "parameters": {
            "alert": {
                "rule": {"id": "100580", "description": "FortiGate configuration changed"},
                "agent": {"name": "fw-edge"},
                "data": {},
            }
        },
    }
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps(message)))

    assert ar.main() == 3
    assert calls == [("fg-120g-01", "wazuh rule 100580: FortiGate configuration changed", "fw-edge")]


def test_ar_script_handles_delete_and_garbage(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("NETAUDIT_AR_LOG", str(tmp_path / "ar.log"))
    ar = _load_ar_script()

    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({"command": "delete"})))
    assert ar.main() == 0

    monkeypatch.setattr("sys.stdin", _stdin("not json"))
    assert ar.main() == 1

    monkeypatch.setattr("sys.stdin", _stdin(""))
    assert ar.main() == 1

    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({"command": "add", "parameters": {}})))
    assert ar.main() == 1

    log = (tmp_path / "ar.log").read_text(encoding="utf-8")
    assert "nothing to roll back" in log
    assert "not valid JSON" in log


class _stdin:
    """Minimal stdin stub: the AR protocol is one JSON line."""

    def __init__(self, text: str) -> None:
        self._text = text

    def readline(self) -> str:
        return self._text
