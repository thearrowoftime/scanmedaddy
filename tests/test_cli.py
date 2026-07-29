"""End-to-end CLI smoke tests (no network, no real devices)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from netaudit import runner as runner_mod
from netaudit.cli import main
from netaudit.ssh_backup import SSHBackupError

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"

INVENTORY = """\
devices:
  - name: fg-120g-01
    host: 127.0.0.1
    device_type: firewall
    platform: fortigate
    username: admin
    password: env:FG_TEST_PW
    port: 22
    tags: [edge, lab]

  - name: scalance-xc208-01
    host: 127.0.0.1
    device_type: switch
    platform: scalance_xc
    username: admin
    password: env:SCALANCE_TEST_PW
    port: 22
    tags: [ot]
"""


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "inventory.yaml").write_text(INVENTORY, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FG_TEST_PW", raising=False)
    monkeypatch.delenv("SCALANCE_TEST_PW", raising=False)
    return tmp_path


def test_secrets_reports_unresolved(workspace: Path):
    result = CliRunner().invoke(main, ["secrets"])
    assert result.exit_code == 1
    assert "unresolved" in result.output


def test_secrets_ok_from_dotenv(workspace: Path):
    (workspace / ".env").write_text(
        "FG_TEST_PW=a\nSCALANCE_TEST_PW=b\n", encoding="utf-8"
    )
    result = CliRunner().invoke(main, ["secrets"])
    assert result.exit_code == 0, result.output
    assert "All credentials resolve" in result.output
    # secrets must never be echoed
    assert "FG_TEST_PW=a" not in result.output


def test_secrets_flags_plaintext_inventory(workspace: Path):
    (workspace / "inventory.yaml").write_text(
        INVENTORY.replace("env:FG_TEST_PW", "hardcoded-pass"), encoding="utf-8"
    )
    (workspace / ".env").write_text("SCALANCE_TEST_PW=b\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["secrets"])
    assert result.exit_code == 1
    assert "plaintext" in result.output


def test_dry_run_blocks_on_missing_credentials(workspace: Path):
    result = CliRunner().invoke(main, ["backup", "--dry-run", "--no-probe"])
    assert result.exit_code == 1
    assert "blocked" in result.output
    assert not (workspace / "backups" / "fg-120g-01").exists()


def test_dry_run_ready_and_json_report(workspace: Path):
    (workspace / ".env").write_text("FG_TEST_PW=a\nSCALANCE_TEST_PW=b\n", encoding="utf-8")
    result = CliRunner().invoke(
        main,
        ["backup", "--dry-run", "--no-probe", "--json-report", "reports/dry-run.json"],
    )
    assert result.exit_code == 0, result.output
    assert "ready" in result.output

    payload = json.loads((workspace / "reports" / "dry-run.json").read_text(encoding="utf-8"))
    assert payload["mode"] == "dry-run"
    assert payload["devices"] == 2
    assert payload["failed"] == 0


def test_dry_run_tag_filter(workspace: Path):
    (workspace / ".env").write_text("FG_TEST_PW=a\nSCALANCE_TEST_PW=b\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["backup", "--dry-run", "--no-probe", "--tag", "ot"])
    assert result.exit_code == 0, result.output
    assert "scalance-xc208-01" in result.output
    assert "fg-120g-01" not in result.output


def test_run_cycle_with_mocked_ssh(workspace: Path, monkeypatch: pytest.MonkeyPatch):
    (workspace / ".env").write_text("FG_TEST_PW=a\nSCALANCE_TEST_PW=b\n", encoding="utf-8")
    fortigate_cfg = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")

    def fake_backup(device, timeout=None, progress=None, **kwargs):
        if device.name == "scalance-xc208-01":
            raise SSHBackupError("timed out waiting for config output")
        return fortigate_cfg

    monkeypatch.setattr(runner_mod, "backup_device", fake_backup)

    result = CliRunner().invoke(
        main,
        ["run", "--retries", "0", "--wazuh-file", "reports/wazuh-netaudit.json"],
    )
    # exit 1 because one device failed to back up
    assert result.exit_code == 1, result.output

    report = json.loads((workspace / "reports" / "run-report.json").read_text(encoding="utf-8"))
    assert report["failed"] == 1
    assert report["ok"] == 1
    assert report["audit"]["critical"] >= 1

    assert (workspace / "reports" / "audit.md").exists()
    assert (workspace / "reports" / "audit.csv").exists()

    events = [
        json.loads(line)
        for line in (workspace / "reports" / "wazuh-netaudit.json")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    types = {e["netaudit"]["event_type"] for e in events}
    assert {"backup_failed", "run_summary", "finding"} <= types


def test_run_clean_exits_two_on_high_findings(workspace: Path, monkeypatch: pytest.MonkeyPatch):
    (workspace / ".env").write_text("FG_TEST_PW=a\nSCALANCE_TEST_PW=b\n", encoding="utf-8")
    fortigate_cfg = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")
    monkeypatch.setattr(runner_mod, "backup_device", lambda *a, **k: fortigate_cfg)

    result = CliRunner().invoke(main, ["run", "--retries", "0"])
    # both devices backed up, but the config has critical findings
    assert result.exit_code == 2, result.output


def test_wazuh_samples_generates_syslog_lines(workspace: Path):
    out = workspace / "samples.log"
    result = CliRunner().invoke(
        main,
        [
            "wazuh-samples",
            "--file",
            str(SAMPLES / "fg-120g-01.cfg"),
            "--platform",
            "fortigate",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 3
    assert all(line.startswith("<134>") for line in lines)
    payloads = [json.loads(line.split("netaudit: ", 1)[1]) for line in lines]
    types = {p["netaudit"]["event_type"] for p in payloads}
    assert {"finding", "backup_failed", "config_changed", "run_summary"} <= types


def test_init_writes_inventory_without_plaintext(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["init"])
    assert result.exit_code == 0, result.output
    inventory = (tmp_path / "inventory.yaml").read_text(encoding="utf-8")
    assert "CHANGE_ME" not in inventory
    assert "env:" in inventory
    assert "wincred:" in inventory


def test_demo_backup_and_audit_still_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["backup", "--demo", "--samples", str(SAMPLES)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(main, ["audit"])
    # sample configs intentionally contain critical findings
    assert result.exit_code == 2, result.output
    assert "critical" in result.output
