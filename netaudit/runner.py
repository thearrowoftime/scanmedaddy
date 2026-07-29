"""Unattended backup runs: dry-run validation, retries, and failure alerts."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from netaudit.audit import audit_config, load_rules
from netaudit.diff import diff_backups, format_diff_markdown
from netaudit.facts import extract_facts, firmware_findings
from netaudit.models import Device, Severity
from netaudit.secrets import SecretStatus, resolve_device_secrets
from netaudit.ssh_backup import (
    DEFAULT_KNOWN_HOSTS,
    HostKeyEvent,
    HostKeyMismatch,
    HostKeyUnknown,
    SSHBackupError,
    backup_device,
    check_reachable,
    is_host_pinned,
)
from netaudit.store import ConfigStore
from netaudit.wazuh_integration import (
    export_wazuh_events_ndjson,
    finding_to_wazuh_event,
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
    known_hosts: str | None = str(DEFAULT_KNOWN_HOSTS),
    strict_host_keys: bool = False,
    progress: ProgressFn | None = None,
) -> tuple[RunReport, list[SecretStatus]]:
    """
    Validate a scheduled run without touching the config store.

    Checks inventory completeness, resolves credentials (values are never
    printed), reports whether the host key is pinned, and optionally TCP-probes
    each device.
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
        pinned = is_host_pinned(device.host, device.port, known_hosts)
        detail_parts.append("host key pinned" if pinned else "host key not pinned")
        if strict_host_keys and not pinned:
            problems.append(
                f"host key for {device.host}:{device.port} is not pinned in {known_hosts}"
            )
        if device.jump is not None:
            detail_parts.append(f"via {device.jump.label}")

        if probe and not problems:
            target = device.jump.host if device.jump is not None else device.host
            target_port = device.jump.port if device.jump is not None else device.port
            reachable, probe_detail = check_reachable(
                replace(resolved, host=target, port=target_port), timeout=probe_timeout
            )
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
    known_hosts: str | None = str(DEFAULT_KNOWN_HOSTS),
    strict_host_keys: bool = False,
    on_host_key: Callable[[HostKeyEvent], None] | None = None,
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
            config = backup_device(
                resolved,
                timeout=timeout,
                progress=log,
                known_hosts=known_hosts,
                strict_host_keys=strict_host_keys,
                on_host_key=on_host_key,
            )
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
        except (HostKeyMismatch, HostKeyUnknown) as exc:
            # A key problem is never transient: retrying only hides it.
            log(f"{device.name}: {exc}")
            return DeviceResult(
                device=device.name,
                platform=device.platform,
                status="blocked",
                attempts=attempts,
                error=str(exc),
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


@dataclass
class RespondReport:
    """Outcome of an alert-triggered backup (Wazuh Active Response)."""

    device: str
    triggered_by: str = ""
    agent: str = ""
    status: str = "unchanged"  # unchanged | changed | failed | blocked
    attempts: int = 0
    added: int = 0
    removed: int = 0
    findings: int = 0
    serious_findings: int = 0
    error: str = ""
    diff_markdown: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.status == "changed"

    @property
    def failed(self) -> bool:
        return self.status in ("failed", "blocked")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("diff_markdown", None)
        data.pop("events", None)
        data["changed"] = self.changed
        return data


def respond_to_alert(
    device: Device,
    store: ConfigStore,
    *,
    triggered_by: str = "",
    agent: str = "",
    retries: int = 1,
    retry_delay: float = 2.0,
    timeout: int | None = None,
    known_hosts: str | None = str(DEFAULT_KNOWN_HOSTS),
    strict_host_keys: bool = False,
    rules_path: str | None = None,
    platform: str | None = None,
    firmware_policy: dict[str, Any] | None = None,
    alerts: AlertSink | None = None,
    progress: ProgressFn | None = None,
) -> RespondReport:
    """
    Pull a fresh config because something happened, then say what changed.

    This is the reverse direction from scheduled runs: Wazuh sees a config
    change on the device (or netaudit's own host key alert) and asks netaudit for
    evidence right away, instead of waiting for the next nightly backup.
    """
    log = progress or (lambda _m: None)
    report = RespondReport(device=device.name, triggered_by=triggered_by, agent=agent)

    result = backup_with_retry(
        device,
        store,
        retries=retries,
        retry_delay=retry_delay,
        timeout=timeout,
        known_hosts=known_hosts,
        strict_host_keys=strict_host_keys,
        on_host_key=lambda ev: report.events.append(_host_key_event(ev)),
        progress=log,
    )
    report.attempts = result.attempts

    if result.failed:
        report.status = result.status
        report.error = result.error
        report.events.append(
            operational_event(
                "respond_failed",
                device=device.name,
                severity=Severity.HIGH.value,
                detail=f"Alert-triggered backup failed for {device.name}: {result.error}",
                platform=device.platform,
                triggered_by=triggered_by,
                agent=agent,
                attempts=result.attempts,
            )
        )
        _emit(report.events, alerts)
        return report

    report.status = "changed" if result.changed else "unchanged"

    if result.changed:
        try:
            diff = diff_backups(store, device.name)
        except FileNotFoundError:
            diff = None
        if diff is not None:
            report.added = len(diff.added)
            report.removed = len(diff.removed)
            report.diff_markdown = format_diff_markdown(diff)
        report.events.append(
            operational_event(
                "config_changed",
                device=device.name,
                severity=Severity.MEDIUM.value,
                detail=(
                    f"Configuration changed on {device.name} "
                    f"({report.added} added, {report.removed} removed)"
                ),
                platform=device.platform,
                path=result.path,
                added_lines=report.added,
                removed_lines=report.removed,
                added_sample=[ln.strip() for ln in (diff.added[:10] if diff else [])],
                removed_sample=[ln.strip() for ln in (diff.removed[:10] if diff else [])],
                triggered_by=triggered_by,
                agent=agent,
            )
        )

    _meta, config = store.get(device.name)
    effective_platform = platform or device.platform
    rules = load_rules(rules_path, platform=effective_platform)
    findings = audit_config(device.name, config, rules, platform=effective_platform)
    if firmware_policy is not None:
        facts = extract_facts(device.name, config, effective_platform)
        findings.extend(firmware_findings(facts, firmware_policy))

    report.findings = len(findings)
    report.serious_findings = sum(
        1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    report.events.extend(finding_to_wazuh_event(f) for f in findings)
    report.events.append(
        operational_event(
            "respond_summary",
            device=device.name,
            severity=Severity.MEDIUM.value if result.changed else Severity.INFO.value,
            detail=(
                f"Alert-triggered backup of {device.name}: {report.status}, "
                f"{report.findings} finding(s), {report.serious_findings} critical/high"
            ),
            platform=device.platform,
            triggered_by=triggered_by,
            agent=agent,
            changed=result.changed,
            findings_total=report.findings,
            findings_serious=report.serious_findings,
        )
    )
    _emit(report.events, alerts)
    return report


def _emit(events: list[dict[str, Any]], alerts: AlertSink | None) -> None:
    if alerts is not None and events:
        alerts.emit(events)


def _host_key_event(event: HostKeyEvent) -> dict[str, Any]:
    """Turn a host key observation into a Wazuh event."""
    if event.status == "mismatch":
        return operational_event(
            "host_key_changed",
            device=event.device,
            severity=Severity.CRITICAL.value,
            detail=(
                f"SSH host key for {event.target} changed: pinned {event.expected}, "
                f"got {event.fingerprint}"
            ),
            target=event.target,
            fingerprint=event.fingerprint,
            expected_fingerprint=event.expected,
        )
    if event.status == "unknown":
        return operational_event(
            "host_key_unpinned",
            device=event.device,
            severity=Severity.MEDIUM.value,
            detail=f"SSH host key for {event.target} is not pinned ({event.fingerprint})",
            target=event.target,
            fingerprint=event.fingerprint,
        )
    return operational_event(
        "host_key_learned",
        device=event.device,
        severity=Severity.INFO.value,
        detail=f"Pinned SSH host key for {event.target} ({event.fingerprint})",
        target=event.target,
        fingerprint=event.fingerprint,
    )


def run_backups(
    devices: list[Device],
    store: ConfigStore,
    *,
    retries: int = 2,
    retry_delay: float = 5.0,
    timeout: int | None = None,
    known_hosts: str | None = str(DEFAULT_KNOWN_HOSTS),
    strict_host_keys: bool = False,
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
            known_hosts=known_hosts,
            strict_host_keys=strict_host_keys,
            on_host_key=lambda ev: events.append(_host_key_event(ev)),
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
