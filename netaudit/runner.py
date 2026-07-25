"""Unattended backup runs: dry-run validation, retries, and failure alerts."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from netaudit.models import Device, Severity
from netaudit.secrets import SecretStatus, resolve_device_secrets
from netaudit.ssh_backup import SSHBackupError, backup_device, check_reachable
from netaudit.store import ConfigStore
from netaudit.wazuh_integration import (
    export_wazuh_events_ndjson,
    operational_event,
    send_wazuh_events_syslog,
)

ProgressFn = Callable[[str], None]


@dataclass
class AlertSink:
    """Where backup failures / run summaries are shipped."""

    wazuh_file: str | None = None
    wazuh_syslog: str | None = None
    wazuh_syslog_port: int = 514
    wazuh_syslog_proto: str = "udp"

    @property
    def enabled(self) -> bool:
        return bool(self.wazuh_file or self.wazuh_syslog)

    def emit(self, events: list[dict[str, Any]]) -> list[str]:
        """Deliver events, returning human-readable delivery notes."""
        notes: list[str] = []
        if not events:
            return notes
        if self.wazuh_file:
            export_wazuh_events_ndjson(events, self.wazuh_file)
            notes.append(f"{len(events)} event(s) -> {self.wazuh_file}")
        if self.wazuh_syslog:
            sent = send_wazuh_events_syslog(
                events,
                self.wazuh_syslog,
                port=self.wazuh_syslog_port,
                protocol=self.wazuh_syslog_proto,
            )
            notes.append(
                f"{sent} event(s) -> {self.wazuh_syslog}:{self.wazuh_syslog_port}"
                f"/{self.wazuh_syslog_proto}"
            )
        return notes


@dataclass
class DeviceResult:
    device: str
    platform: str
    status: str  # ok | unchanged | failed | ready | blocked
    attempts: int = 0
    error: str | None = None
    path: str | None = None
    size_bytes: int | None = None
    changed: bool = False
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.status in ("failed", "blocked")


@dataclass
class RunReport:
    started_at: str
    finished_at: str = ""
    mode: str = "backup"  # backup | dry-run
    results: list[DeviceResult] = field(default_factory=list)
    alerts_sent: list[str] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.status in ("ok", "unchanged", "ready"))

    @property
    def changed_count(self) -> int:
        return sum(1 for r in self.results if r.changed)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.failed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "mode": self.mode,
            "devices": len(self.results),
            "ok": self.ok_count,
            "changed": self.changed_count,
            "failed": self.fail_count,
            "alerts_sent": self.alerts_sent,
            "results": [asdict(r) for r in self.results],
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dry_run(
    devices: list[Device],
    *,
    probe: bool = True,
    probe_timeout: float = 5.0,
    progress: ProgressFn | None = None,
) -> tuple[RunReport, list[SecretStatus]]:
    """
    Validate a scheduled run without touching the config store.

    Checks inventory completeness, resolves credentials (values are never
    printed), and optionally TCP-probes each device.
    """
    log = progress or (lambda _m: None)
    report = RunReport(started_at=_now(), mode="dry-run")
    statuses: list[SecretStatus] = []

    for device in devices:
        resolved, device_statuses = resolve_device_secrets(device, allow_prompt=False)
        statuses.extend(device_statuses)

        problems = [s.detail or f"{s.field} unresolved" for s in device_statuses if not s.resolved]
        if not resolved.username:
            problems.append("username missing in inventory")

        detail_parts: list[str] = []
        if probe and not problems:
            reachable, probe_detail = check_reachable(resolved, timeout=probe_timeout)
            detail_parts.append(probe_detail)
            if not reachable:
                problems.append(probe_detail)

        status = "ready" if not problems else "blocked"
        log(
            f"{device.name}: {status}"
            + (f" ({'; '.join(problems)})" if problems else f" ({'; '.join(detail_parts)})")
        )
        report.results.append(
            DeviceResult(
                device=device.name,
                platform=device.platform,
                status=status,
                error="; ".join(problems) or None,
                detail="; ".join(detail_parts),
            )
        )

    report.finished_at = _now()
    return report, statuses


def backup_with_retry(
    device: Device,
    store: ConfigStore,
    *,
    retries: int = 2,
    retry_delay: float = 5.0,
    timeout: int | None = None,
    progress: ProgressFn | None = None,
) -> DeviceResult:
    """Back up one device, retrying transient SSH failures."""
    log = progress or (lambda _m: None)
    attempts = 0
    last_error = ""

    resolved, statuses = resolve_device_secrets(device, allow_prompt=False)
    unresolved = [s for s in statuses if not s.resolved]
    if unresolved:
        detail = "; ".join(s.detail or f"{s.field} unresolved" for s in unresolved)
        log(f"{device.name}: credential problem - {detail}")
        return DeviceResult(
            device=device.name,
            platform=device.platform,
            status="blocked",
            attempts=0,
            error=f"credentials unresolved: {detail}",
        )

    previous = store.latest(device.name)
    total_tries = max(1, retries + 1)

    while attempts < total_tries:
        attempts += 1
        try:
            config = backup_device(resolved, timeout=timeout, progress=log)
            meta = store.save(device.name, config, source="ssh")
            changed = previous is None or previous.sha256 != meta.sha256
            return DeviceResult(
                device=device.name,
                platform=device.platform,
                status="ok" if changed else "unchanged",
                attempts=attempts,
                path=meta.path,
                size_bytes=meta.size_bytes,
                changed=changed,
            )
        except SSHBackupError as exc:
            last_error = str(exc)
            if attempts < total_tries:
                log(f"{device.name}: attempt {attempts}/{total_tries} failed, retrying in {retry_delay}s")
                time.sleep(retry_delay)
            else:
                log(f"{device.name}: attempt {attempts}/{total_tries} failed")

    return DeviceResult(
        device=device.name,
        platform=device.platform,
        status="failed",
        attempts=attempts,
        error=last_error,
    )


def run_backups(
    devices: list[Device],
    store: ConfigStore,
    *,
    retries: int = 2,
    retry_delay: float = 5.0,
    timeout: int | None = None,
    alerts: AlertSink | None = None,
    progress: ProgressFn | None = None,
) -> RunReport:
    """Back up every device, alerting on SSH failures and summarising the run."""
    report = RunReport(started_at=_now(), mode="backup")
    events: list[dict[str, Any]] = []

    for device in devices:
        result = backup_with_retry(
            device,
            store,
            retries=retries,
            retry_delay=retry_delay,
            timeout=timeout,
            progress=progress,
        )
        report.results.append(result)

        if result.failed:
            events.append(
                operational_event(
                    "backup_failed",
                    device=result.device,
                    severity=Severity.HIGH.value,
                    detail=f"Config backup failed for {result.device}: {result.error}",
                    platform=result.platform,
                    attempts=result.attempts,
                    error=result.error,
                )
            )
        elif result.changed:
            events.append(
                operational_event(
                    "config_changed",
                    device=result.device,
                    severity=Severity.MEDIUM.value,
                    detail=f"Configuration changed on {result.device}",
                    platform=result.platform,
                    path=result.path,
                )
            )

    report.finished_at = _now()

    events.append(
        operational_event(
            "run_summary",
            severity=Severity.HIGH.value if report.fail_count else Severity.INFO.value,
            detail=(
                f"Backup run finished: {report.ok_count} ok, "
                f"{report.changed_count} changed, {report.fail_count} failed"
            ),
            devices=len(report.results),
            ok=report.ok_count,
            changed=report.changed_count,
            failed=report.fail_count,
        )
    )

    if alerts and alerts.enabled:
        report.alerts_sent = alerts.emit(events)

    return report
