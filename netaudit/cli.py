"""CLI for Network Audit and Config Backup."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from netaudit import __version__
from netaudit.audit import (
    audit_config,
    infer_platform_from_config,
    load_rules,
    summarize_findings,
)
from netaudit.baseline import BaselineProfile, compare_to_baseline
from netaudit.compliance import (
    attach_previous,
    control_rollup,
    load_framework_map,
    load_history,
    overall_score,
    record_history,
    score_device,
    score_findings,
    unmapped_rules,
)
from netaudit.diff import diff_backups
from netaudit.export import (
    export_compliance_csv,
    export_compliance_markdown,
    export_diff_csv,
    export_diff_markdown,
    export_findings_csv,
    export_findings_markdown,
)
from netaudit.facts import DeviceFacts, extract_facts, firmware_findings, load_firmware_policy
from netaudit.inventory import load_inventory, platform_for_device, save_inventory_template
from netaudit.models import Device, Finding, Severity
from netaudit.runner import AlertSink, RunReport, dry_run, respond_to_alert, run_backups
from netaudit.secrets import DEFAULT_ENV_FILE, load_env_file, resolve_inventory_secrets
from netaudit.ssh_backup import DEFAULT_KNOWN_HOSTS, host_key_name, key_fingerprint
from netaudit.store import ConfigStore
from netaudit.wazuh_integration import (
    export_wazuh_ndjson,
    finding_to_wazuh_event,
    format_syslog_line,
    send_wazuh_api,
    send_wazuh_syslog,
)

# Force UTF-8 friendly output on Windows consoles (cp1252 breaks on arrows etc.)
console = Console(force_terminal=True, legacy_windows=False)
SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
SOURCE_STYLE = {
    "inline": "red",
    "missing": "red",
    "unset": "dim",
}


def _store(ctx: click.Context) -> ConfigStore:
    return ConfigStore(ctx.obj["backups"])


def _load_devices(ctx: click.Context, device_filter: str | None, tag: str | None) -> list[Device]:
    try:
        devices = load_inventory(ctx.obj["inventory"])
    except FileNotFoundError:
        console.print(
            f"[red]Inventory not found:[/] {ctx.obj['inventory']}\n"
            "Run [bold]netaudit init[/] first."
        )
        sys.exit(1)

    if device_filter:
        devices = [d for d in devices if d.name == device_filter]
        if not devices:
            console.print(f"[red]Device not in inventory:[/] {device_filter}")
            sys.exit(1)
    if tag:
        devices = [d for d in devices if tag in d.tags]
        if not devices:
            console.print(f"[red]No devices with tag:[/] {tag}")
            sys.exit(1)
    return devices


def _print_run_report(report: RunReport) -> None:
    table = Table(title=f"Backup run ({report.mode})")
    table.add_column("Device")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Tries")
    table.add_column("Detail")
    status_style = {
        "ok": "green",
        "unchanged": "dim",
        "ready": "green",
        "failed": "red",
        "blocked": "red",
    }
    for result in report.results:
        style = status_style.get(result.status, "")
        detail = result.error or result.detail or (result.path or "")
        if len(detail) > 70:
            detail = detail[:67] + "..."
        table.add_row(
            result.device,
            result.platform,
            f"[{style}]{result.status}[/]",
            str(result.attempts or "-"),
            detail,
        )
    console.print(table)
    console.print(
        Panel(
            f"ok=[green]{report.ok_count}[/]  changed=[yellow]{report.changed_count}[/]  "
            f"failed=[red]{report.fail_count}[/]"
        )
    )
    for note in report.alerts_sent:
        console.print(f"[green]Alert[/] {note}")


def _write_json_report(report: RunReport, path: str, extra: dict | None = None) -> None:
    payload = report.to_dict()
    if extra:
        payload.update(extra)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote[/] {path}")


def _alert_sink(
    wazuh_file: str | None,
    wazuh_syslog: str | None,
    port: int,
    proto: str,
) -> AlertSink:
    return AlertSink(
        wazuh_file=wazuh_file,
        wazuh_syslog=wazuh_syslog,
        wazuh_syslog_port=port,
        wazuh_syslog_proto=proto,
    )


def _audit_devices(
    ctx: click.Context,
    store: ConfigStore,
    device_names: list[str],
    rules_path: str | None,
    platform_override: str | None,
    firmware_policy: dict | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for name in device_names:
        try:
            _meta, text = store.get(name)
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/]")
            continue
        platform = (
            platform_override
            or platform_for_device(ctx.obj["inventory"], name)
            or infer_platform_from_config(text)
        )
        rules = load_rules(rules_path, platform=platform)
        findings.extend(audit_config(name, text, rules, platform=platform))
        if firmware_policy is not None:
            facts = extract_facts(name, text, platform)
            findings.extend(firmware_findings(facts, firmware_policy))
    return findings


def _facts_table(all_facts: list[DeviceFacts]) -> Table:
    table = Table(title="Device inventory facts")
    table.add_column("Device")
    table.add_column("Platform")
    table.add_column("Model")
    table.add_column("Firmware")
    table.add_column("VLANs")
    table.add_column("Interfaces")
    table.add_column("Admins")
    for facts in all_facts:
        table.add_row(
            facts.hostname or facts.device,
            facts.platform,
            facts.model or "-",
            facts.firmware_label,
            ", ".join(facts.vlans) or "-",
            str(len(facts.interfaces)),
            ", ".join(facts.admins) or "-",
        )
    return table


def _print_findings(findings: list[Finding]) -> dict[str, int]:
    summary = summarize_findings(findings)
    table = Table(title="Audit findings")
    table.add_column("Sev")
    table.add_column("Device")
    table.add_column("Rule")
    table.add_column("Evidence / detail")
    for f in findings:
        style = SEVERITY_STYLE.get(f.severity.value, "")
        evidence = f.evidence or f.detail
        if len(evidence) > 80:
            evidence = evidence[:77] + "..."
        table.add_row(f"[{style}]{f.severity.value}[/]", f.device, f.rule_id, evidence)
    console.print(table)
    console.print(
        Panel(
            f"total={summary['total']}  "
            f"critical={summary['critical']}  high={summary['high']}  "
            f"medium={summary['medium']}  low={summary['low']}"
        )
    )
    return summary


@click.group()
@click.version_option(__version__, prog_name="netaudit")
@click.option(
    "--backups",
    default="backups",
    show_default=True,
    type=click.Path(),
    help="Directory for config snapshots",
)
@click.option(
    "--inventory",
    default="inventory.yaml",
    show_default=True,
    type=click.Path(),
    help="Device inventory YAML",
)
@click.option(
    "--env-file",
    default=DEFAULT_ENV_FILE,
    show_default=True,
    type=click.Path(),
    help="Dotenv file with credential variables",
)
@click.option(
    "--known-hosts",
    default=str(DEFAULT_KNOWN_HOSTS),
    show_default=True,
    type=click.Path(),
    help="File with pinned SSH host keys",
)
@click.pass_context
def main(
    ctx: click.Context, backups: str, inventory: str, env_file: str, known_hosts: str
) -> None:
    """Network Audit and Config Backup - SSH backup, diff, security audit."""
    ctx.ensure_object(dict)
    ctx.obj["backups"] = backups
    ctx.obj["inventory"] = inventory
    ctx.obj["env_file"] = env_file
    ctx.obj["known_hosts"] = known_hosts
    ctx.obj["env_loaded"] = load_env_file(env_file)


@main.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing inventory.yaml")
@click.pass_context
def init_cmd(ctx: click.Context, force: bool) -> None:
    """Create example inventory.yaml and folders."""
    inv = Path(ctx.obj["inventory"])
    if inv.exists() and not force:
        console.print(f"[yellow]Inventory already exists:[/] {inv} (use --force)")
    else:
        save_inventory_template(inv)
        console.print(f"[green]Wrote[/] {inv}")
    Path(ctx.obj["backups"]).mkdir(parents=True, exist_ok=True)
    Path("reports").mkdir(parents=True, exist_ok=True)
    console.print(
        "[green]Ready.[/] Put credentials in .env (see .env.example), "
        "then run: netaudit backup --dry-run"
    )


@main.command("secrets")
@click.option("--device", "device_filter", default=None, help="Check one device")
@click.option("--tag", default=None, help="Check devices carrying this tag")
@click.pass_context
def secrets_cmd(ctx: click.Context, device_filter: str | None, tag: str | None) -> None:
    """Show how each credential resolves (values are never printed)."""
    devices = _load_devices(ctx, device_filter, tag)
    _resolved, statuses = resolve_inventory_secrets(devices, allow_prompt=False)

    env_file = ctx.obj["env_file"]
    loaded = ctx.obj["env_loaded"]
    if loaded:
        console.print(f"[dim]Loaded {len(loaded)} variable(s) from {env_file}[/]")

    table = Table(title="Credential resolution")
    table.add_column("Device")
    table.add_column("Field")
    table.add_column("Reference")
    table.add_column("Source")
    table.add_column("Status")
    for status in statuses:
        style = SOURCE_STYLE.get(status.source, "green")
        state = "[green]ok[/]" if status.resolved else "[red]unresolved[/]"
        if status.inline_plaintext:
            state = "[red]plaintext in inventory[/]"
        table.add_row(
            status.device,
            status.field,
            status.reference or "-",
            f"[{style}]{status.source}[/]",
            f"{state} {status.detail}".strip(),
        )
    console.print(table)

    inline = [s for s in statuses if s.inline_plaintext]
    missing = [s for s in statuses if not s.resolved]
    if inline:
        console.print(
            f"[red]{len(inline)} credential(s) stored as plaintext in the inventory.[/] "
            "Move them to .env / Credential Manager and use env: or wincred: references."
        )
    if missing:
        console.print(f"[red]{len(missing)} credential(s) unresolved.[/]")
        sys.exit(1)
    if inline:
        sys.exit(1)
    console.print("[green]All credentials resolve from external stores.[/]")


@main.command("backup")
@click.option("--device", "device_filter", default=None, help="Backup only this device name")
@click.option("--tag", default=None, help="Backup devices carrying this tag")
@click.option("--demo", is_flag=True, help="Import sample configs instead of SSH")
@click.option(
    "--samples",
    default="samples",
    type=click.Path(),
    show_default=True,
    help="Sample configs dir (with --demo)",
)
@click.option(
    "--dry-run",
    "dry_run_mode",
    is_flag=True,
    help="Validate inventory, credentials and reachability only",
)
@click.option("--no-probe", is_flag=True, help="Skip the TCP probe during --dry-run")
@click.option("--retries", default=2, show_default=True, type=int, help="Retries per device")
@click.option("--retry-delay", default=5.0, show_default=True, type=float, help="Seconds between retries")
@click.option("--timeout", default=None, type=int, help="SSH read timeout override (seconds)")
@click.option("--alert-wazuh-file", "alert_file", default=None, type=click.Path(), help="NDJSON file for failure alerts")
@click.option("--alert-wazuh-syslog", "alert_syslog", default=None, help="Syslog host for failure alerts")
@click.option("--alert-wazuh-syslog-port", "alert_port", default=514, show_default=True, type=int)
@click.option("--alert-wazuh-syslog-proto", "alert_proto", default="udp", type=click.Choice(["udp", "tcp"]))
@click.option("--json-report", default=None, type=click.Path(), help="Write run report as JSON")
@click.option(
    "--strict-host-keys",
    is_flag=True,
    help="Refuse devices whose SSH host key is not pinned yet",
)
@click.pass_context
def backup_cmd(
    ctx: click.Context,
    device_filter: str | None,
    tag: str | None,
    demo: bool,
    samples: str,
    dry_run_mode: bool,
    no_probe: bool,
    retries: int,
    retry_delay: float,
    timeout: int | None,
    alert_file: str | None,
    alert_syslog: str | None,
    alert_port: int,
    alert_proto: str,
    json_report: str | None,
    strict_host_keys: bool,
) -> None:
    """Backup running configs over SSH (or import demo samples)."""
    store = _store(ctx)

    if demo:
        sample_dir = Path(samples)
        files = sorted(sample_dir.glob("*.cfg")) + sorted(sample_dir.glob("*.txt"))
        # Skip *-v2.cfg - those are for import-config / diff demos
        files = [f for f in files if not f.stem.endswith("-v2")]
        if not files:
            console.print(f"[red]No sample configs in {sample_dir}[/]")
            sys.exit(1)
        for f in files:
            name = f.stem
            if device_filter and name != device_filter:
                continue
            meta = store.import_file(name, f, source="demo")
            console.print(
                f"[green]OK[/] {name} -> {meta.path} ({meta.size_bytes} B, {meta.sha256[:12]}...)"
            )
        return

    devices = _load_devices(ctx, device_filter, tag)

    if dry_run_mode:
        report, _statuses = dry_run(
            devices,
            probe=not no_probe,
            known_hosts=ctx.obj["known_hosts"],
            strict_host_keys=strict_host_keys,
            progress=lambda m: console.print(f"  [dim]{m}[/]"),
        )
        _print_run_report(report)
        if json_report:
            _write_json_report(report, json_report)
        console.print("[dim]Dry run: nothing was written to the config store.[/]")
        sys.exit(1 if report.fail_count else 0)

    report = run_backups(
        devices,
        store,
        retries=retries,
        retry_delay=retry_delay,
        timeout=timeout,
        known_hosts=ctx.obj["known_hosts"],
        strict_host_keys=strict_host_keys,
        alerts=_alert_sink(alert_file, alert_syslog, alert_port, alert_proto),
        progress=lambda m: console.print(f"  [dim]{m}[/]"),
    )
    _print_run_report(report)
    if json_report:
        _write_json_report(report, json_report)
    if report.fail_count:
        sys.exit(1)


@main.command("hostkeys")
@click.option("--forget", default=None, help="Remove the pin for HOST or HOST:PORT")
@click.pass_context
def hostkeys_cmd(ctx: click.Context, forget: str | None) -> None:
    """List pinned SSH host keys (and drop one after a legitimate replacement)."""
    import paramiko

    path = Path(ctx.obj["known_hosts"])
    if not path.exists():
        console.print(f"[yellow]No pinned keys yet:[/] {path}")
        console.print("[dim]Run netaudit backup once to pin device keys.[/]")
        return

    keys = paramiko.HostKeys()
    keys.load(str(path))

    if forget:
        host, _, port = forget.partition(":")
        entry = host_key_name(host, int(port)) if port else forget
        if entry not in keys:
            console.print(f"[red]Not pinned:[/] {entry}")
            sys.exit(1)
        del keys[entry]
        keys.save(str(path))
        console.print(f"[green]Removed pin[/] {entry} from {path}")
        console.print("[dim]The next backup will pin the new key and report it.[/]")
        return

    table = Table(title=f"Pinned host keys ({path})")
    table.add_column("Host")
    table.add_column("Key type")
    table.add_column("Fingerprint")
    for hostname in sorted(keys.keys()):
        for keytype, key in keys[hostname].items():
            table.add_row(hostname, keytype, key_fingerprint(key))
    console.print(table)


@main.command("run")
@click.option("--device", "device_filter", default=None, help="Limit to one device")
@click.option("--tag", default=None, help="Limit to devices carrying this tag")
@click.option("--retries", default=2, show_default=True, type=int)
@click.option("--retry-delay", default=5.0, show_default=True, type=float)
@click.option("--timeout", default=None, type=int, help="SSH read timeout override (seconds)")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True))
@click.option("--report-dir", default="reports", show_default=True, type=click.Path())
@click.option(
    "--wazuh-file",
    default=None,
    type=click.Path(),
    help="NDJSON file for findings and run alerts (Wazuh agent localfile)",
)
@click.option("--wazuh-syslog", default=None, help="Syslog host for findings and run alerts")
@click.option("--wazuh-syslog-port", default=514, show_default=True, type=int)
@click.option("--wazuh-syslog-proto", default="udp", type=click.Choice(["udp", "tcp"]))
@click.option("--skip-audit", is_flag=True, help="Backup only, no audit stage")
@click.option(
    "--strict-host-keys",
    is_flag=True,
    help="Refuse devices whose SSH host key is not pinned yet",
)
@click.option(
    "--baseline",
    "profile_path",
    default=None,
    type=click.Path(exists=True),
    help="Also report golden config drift from this baseline profile",
)
@click.option(
    "--compliance-history",
    default=None,
    type=click.Path(),
    help="Record compliance scores in this file (enables the trend)",
)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    device_filter: str | None,
    tag: str | None,
    retries: int,
    retry_delay: float,
    timeout: int | None,
    rules_path: str | None,
    report_dir: str,
    wazuh_file: str | None,
    wazuh_syslog: str | None,
    wazuh_syslog_port: int,
    wazuh_syslog_proto: str,
    skip_audit: bool,
    strict_host_keys: bool,
    profile_path: str | None,
    compliance_history: str | None,
) -> None:
    """
    One-shot scheduled cycle: backup with retries, audit, export, alert.

    Exit codes: 0 clean, 1 backup failure, 2 critical/high findings.
    """
    store = _store(ctx)
    devices = _load_devices(ctx, device_filter, tag)
    alerts = _alert_sink(wazuh_file, wazuh_syslog, wazuh_syslog_port, wazuh_syslog_proto)

    report = run_backups(
        devices,
        store,
        retries=retries,
        retry_delay=retry_delay,
        timeout=timeout,
        known_hosts=ctx.obj["known_hosts"],
        strict_host_keys=strict_host_keys,
        alerts=alerts,
        progress=lambda m: console.print(f"  [dim]{m}[/]"),
    )
    _print_run_report(report)

    reports = Path(report_dir)
    reports.mkdir(parents=True, exist_ok=True)
    summary: dict[str, int] = {}

    if not skip_audit:
        backed_up = [r.device for r in report.results if not r.failed]
        findings = _audit_devices(
            ctx, store, backed_up, rules_path, None, load_firmware_policy(None)
        )

        if profile_path:
            profile = BaselineProfile.load(profile_path)
            golden = profile.golden_config()
            for name in backed_up:
                _meta, text = store.get(name)
                platform = platform_for_device(
                    ctx.obj["inventory"], name
                ) or infer_platform_from_config(text)
                if profile.applies_to(platform):
                    findings.extend(compare_to_baseline(name, text, profile, golden))

        summary = _print_findings(findings)

        export_findings_markdown(findings, reports / "audit.md")
        export_findings_csv(findings, reports / "audit.csv")
        console.print(f"[green]Wrote[/] {reports / 'audit.md'} and {reports / 'audit.csv'}")

        scores = score_findings(findings)
        for name in backed_up:
            if not any(s.device == name for s in scores):
                scores.append(score_device(name, []))
        if compliance_history:
            history = load_history(compliance_history)
            attach_previous(scores, history)
            record_history(scores, compliance_history)
        controls = control_rollup(findings)
        export_compliance_markdown(
            scores,
            controls,
            reports / "compliance.md",
            findings=findings,
            history=load_history(compliance_history) if compliance_history else None,
            unmapped=unmapped_rules(findings),
        )
        summary["score"] = overall_score(scores)
        console.print(
            f"[green]Wrote[/] {reports / 'compliance.md'} "
            f"(overall score {overall_score(scores)}/100)"
        )

        if wazuh_file:
            export_wazuh_ndjson(findings, wazuh_file)
            console.print(f"[green]Wazuh NDJSON[/] {wazuh_file} ({len(findings)} finding events)")
        if wazuh_syslog:
            sent = send_wazuh_syslog(
                findings, wazuh_syslog, port=wazuh_syslog_port, protocol=wazuh_syslog_proto
            )
            console.print(f"[green]Wazuh syslog[/] {sent} finding events -> {wazuh_syslog}")

    _write_json_report(report, str(reports / "run-report.json"), extra={"audit": summary})

    if report.fail_count:
        sys.exit(1)
    if summary.get("critical") or summary.get("high"):
        sys.exit(2)


@main.command("list")
@click.option("--device", "device_filter", default=None)
@click.pass_context
def list_cmd(ctx: click.Context, device_filter: str | None) -> None:
    """List stored config backups."""
    store = _store(ctx)
    backups = store.list_backups(device_filter)
    if not backups:
        console.print("[yellow]No backups yet.[/]")
        return
    table = Table(title="Config backups")
    table.add_column("Device")
    table.add_column("Timestamp")
    table.add_column("Size")
    table.add_column("Source")
    table.add_column("SHA256")
    for b in backups:
        table.add_row(b.device, b.timestamp, str(b.size_bytes), b.source, b.sha256[:12] + "...")
    console.print(table)


@main.command("diff")
@click.argument("device")
@click.option("--older", default=None, help="Older timestamp (default: previous)")
@click.option("--newer", default=None, help="Newer timestamp (default: latest)")
@click.option("--export", "export_path", default=None, type=click.Path(), help="Write Markdown diff")
@click.option("--csv", "csv_path", default=None, type=click.Path(), help="Write CSV of added/removed")
@click.pass_context
def diff_cmd(
    ctx: click.Context,
    device: str,
    older: str | None,
    newer: str | None,
    export_path: str | None,
    csv_path: str | None,
) -> None:
    """Show unified diff between two backups (default: last two)."""
    store = _store(ctx)
    try:
        result = diff_backups(store, device, older_ts=older, newer_ts=newer)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)

    if not result.has_changes:
        console.print(f"[green]No changes[/] for {device} ({result.older} -> {result.newer})")
    else:
        console.print(
            f"[bold]{device}[/] {result.older} -> {result.newer} "
            f"(+{len(result.added)} / -{len(result.removed)})"
        )
        console.print(Syntax("\n".join(result.changed_hunks), "diff", theme="monokai"))

    if export_path:
        export_diff_markdown(result, export_path)
        console.print(f"[green]Wrote[/] {export_path}")
    if csv_path:
        export_diff_csv(result, csv_path)
        console.print(f"[green]Wrote[/] {csv_path}")


@main.command("audit")
@click.option("--device", "device_filter", default=None, help="Audit one device (latest backup)")
@click.option("--file", "config_file", default=None, type=click.Path(exists=True), help="Audit a local .cfg")
@click.option("--platform", "platform_override", default=None, help="Force platform (fortigate|scalance_xc|cisco_ios|...)")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True))
@click.option(
    "--export",
    "export_md",
    default=None,
    type=click.Path(),
    help="Write Markdown report",
)
@click.option("--csv", "export_csv", default=None, type=click.Path(), help="Write CSV report")
@click.option(
    "--wazuh-file",
    default=None,
    type=click.Path(),
    help="Append findings as NDJSON for Wazuh agent localfile",
)
@click.option("--wazuh-syslog", default=None, help="Send findings via syslog to HOST")
@click.option("--wazuh-syslog-port", default=514, show_default=True, type=int)
@click.option("--wazuh-syslog-proto", default="udp", type=click.Choice(["udp", "tcp"]))
@click.option("--wazuh-api", default=None, help="Wazuh API base URL (e.g. https://manager:55000)")
@click.option("--wazuh-user", default="wazuh", show_default=True)
@click.option("--wazuh-pass", default=None, help="Wazuh API password")
@click.option(
    "--firmware-policy",
    default=None,
    type=click.Path(exists=True),
    help="Minimum firmware versions (defaults to the bundled policy)",
)
@click.option("--skip-firmware", is_flag=True, help="Do not check firmware versions")
@click.pass_context
def audit_cmd(
    ctx: click.Context,
    device_filter: str | None,
    config_file: str | None,
    platform_override: str | None,
    rules_path: str | None,
    export_md: str | None,
    export_csv: str | None,
    wazuh_file: str | None,
    wazuh_syslog: str | None,
    wazuh_syslog_port: int,
    wazuh_syslog_proto: str,
    wazuh_api: str | None,
    wazuh_user: str,
    wazuh_pass: str | None,
    firmware_policy: str | None,
    skip_firmware: bool,
) -> None:
    """Audit configs for dangerous settings and missing standards."""
    store = _store(ctx)
    findings: list[Finding] = []
    policy = None if skip_firmware else load_firmware_policy(firmware_policy)

    if config_file:
        name = Path(config_file).stem
        text = Path(config_file).read_text(encoding="utf-8")
        platform = (
            platform_override
            or infer_platform_from_config(text)
            or platform_for_device(ctx.obj["inventory"], name)
        )
        rules = load_rules(rules_path, platform=platform)
        findings.extend(audit_config(name, text, rules, platform=platform))
        if policy is not None:
            findings.extend(firmware_findings(extract_facts(name, text, platform), policy))
        console.print(f"[dim]platform={platform or 'all'}[/]")
    else:
        if device_filter:
            device_names = [device_filter]
        else:
            device_names = sorted({b.device for b in store.list_backups()})
        if not device_names:
            console.print("[yellow]No backups to audit. Run backup --demo or backup first.[/]")
            sys.exit(1)
        findings.extend(
            _audit_devices(ctx, store, device_names, rules_path, platform_override, policy)
        )

    summary = _print_findings(findings)

    if export_md:
        export_findings_markdown(findings, export_md)
        console.print(f"[green]Wrote[/] {export_md}")
    if export_csv:
        export_findings_csv(findings, export_csv)
        console.print(f"[green]Wrote[/] {export_csv}")

    if wazuh_file:
        export_wazuh_ndjson(findings, wazuh_file)
        console.print(f"[green]Wazuh NDJSON[/] {wazuh_file} ({len(findings)} events)")
    if wazuh_syslog:
        n = send_wazuh_syslog(
            findings, wazuh_syslog, port=wazuh_syslog_port, protocol=wazuh_syslog_proto
        )
        console.print(
            f"[green]Wazuh syslog[/] {n} events -> "
            f"{wazuh_syslog}:{wazuh_syslog_port}/{wazuh_syslog_proto}"
        )
    if wazuh_api:
        if not wazuh_pass:
            console.print("[red]--wazuh-api requires --wazuh-pass[/]")
            sys.exit(1)
        try:
            result = send_wazuh_api(findings, wazuh_api, wazuh_user, wazuh_pass)
            if result.get("ok"):
                console.print(f"[green]Wazuh API[/] posted {result.get('count')} events")
            else:
                console.print(f"[yellow]Wazuh API[/] {result.get('message')}")
        except RuntimeError as exc:
            console.print(f"[red]Wazuh API[/] {exc}")
            sys.exit(1)

    # Non-zero exit if critical/high - useful in CI / scheduled jobs
    if summary["critical"] or summary["high"]:
        sys.exit(2)


@main.command("respond")
@click.option("--device", "device_name", required=True, help="Device from the inventory")
@click.option(
    "--reason",
    "triggered_by",
    default="manual",
    show_default=True,
    help="What triggered this (e.g. the Wazuh rule id)",
)
@click.option("--agent", default="", help="Wazuh agent name that raised the alert")
@click.option("--retries", default=1, show_default=True, type=int)
@click.option("--retry-delay", default=2.0, show_default=True, type=float)
@click.option("--timeout", default=None, type=int, help="SSH read timeout override (seconds)")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True))
@click.option(
    "--wazuh-file",
    default=None,
    type=click.Path(),
    help="NDJSON file for the resulting events (Wazuh agent localfile)",
)
@click.option("--wazuh-syslog", default=None, help="Syslog host for the resulting events")
@click.option("--wazuh-syslog-port", default=514, show_default=True, type=int)
@click.option("--wazuh-syslog-proto", default="udp", type=click.Choice(["udp", "tcp"]))
@click.option(
    "--diff-out", default=None, type=click.Path(), help="Write the diff as Markdown to this path"
)
@click.option("--json-report", default=None, type=click.Path(), help="Write the outcome as JSON")
@click.option("--strict-host-keys", is_flag=True, help="Require a pinned SSH host key")
@click.pass_context
def respond_cmd(
    ctx: click.Context,
    device_name: str,
    triggered_by: str,
    agent: str,
    retries: int,
    retry_delay: float,
    timeout: int | None,
    rules_path: str | None,
    wazuh_file: str | None,
    wazuh_syslog: str | None,
    wazuh_syslog_port: int,
    wazuh_syslog_proto: str,
    diff_out: str | None,
    json_report: str | None,
    strict_host_keys: bool,
) -> None:
    """
    Back up one device right now because an alert fired, then diff and audit it.

    Meant to be called by Wazuh Active Response: the SIEM sees a config change on
    the device and netaudit immediately produces the evidence.

    Exit codes: 0 no change, 1 backup failure, 2 critical/high findings,
    3 configuration changed.
    """
    devices = {d.name: d for d in _load_devices(ctx, None, None)}
    device = devices.get(device_name)
    if device is None:
        console.print(f"[red]Unknown device:[/] {device_name}")
        console.print(f"[dim]Known: {', '.join(sorted(devices)) or 'none'}[/]")
        sys.exit(1)

    report = respond_to_alert(
        device,
        _store(ctx),
        triggered_by=triggered_by,
        agent=agent,
        retries=retries,
        retry_delay=retry_delay,
        timeout=timeout,
        known_hosts=ctx.obj["known_hosts"],
        strict_host_keys=strict_host_keys,
        rules_path=rules_path,
        platform=platform_for_device(ctx.obj["inventory"], device_name) or device.platform,
        firmware_policy=load_firmware_policy(None),
        alerts=_alert_sink(wazuh_file, wazuh_syslog, wazuh_syslog_port, wazuh_syslog_proto),
        progress=lambda m: console.print(f"  [dim]{m}[/]"),
    )

    style = "red" if report.failed else ("yellow" if report.changed else "green")
    console.print(
        Panel(
            f"[{style}]{report.status}[/] {report.device} "
            f"(triggered by {report.triggered_by or 'unknown'})\n"
            f"changed lines: +{report.added} -{report.removed} | "
            f"findings: {report.findings} ({report.serious_findings} critical/high)"
            + (f"\nerror: {report.error}" if report.error else ""),
            title="Active response",
            border_style=style,
        )
    )

    if diff_out and report.diff_markdown:
        p = Path(diff_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.diff_markdown, encoding="utf-8")
        console.print(f"[green]Wrote[/] {diff_out}")
    if json_report:
        p = Path(json_report)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Wrote[/] {json_report}")

    if report.failed:
        sys.exit(1)
    if report.serious_findings:
        sys.exit(2)
    if report.changed:
        sys.exit(3)


@main.command("baseline")
@click.option(
    "--profile",
    "profile_path",
    required=True,
    type=click.Path(exists=True),
    help="Baseline profile YAML (see baselines/)",
)
@click.option("--device", "device_filter", default=None, help="Limit to one device")
@click.option("--file", "config_file", default=None, type=click.Path(exists=True))
@click.option("--export", "export_md", default=None, type=click.Path(), help="Markdown report")
@click.option("--csv", "export_csv", default=None, type=click.Path(), help="CSV report")
@click.pass_context
def baseline_cmd(
    ctx: click.Context,
    profile_path: str,
    device_filter: str | None,
    config_file: str | None,
    export_md: str | None,
    export_csv: str | None,
) -> None:
    """Compare configs against an approved golden template (drift detection)."""
    profile = BaselineProfile.load(profile_path)
    store = _store(ctx)
    findings: list[Finding] = []

    try:
        golden = profile.golden_config()
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)

    if config_file:
        name = Path(config_file).stem
        text = Path(config_file).read_text(encoding="utf-8")
        findings.extend(compare_to_baseline(name, text, profile, golden))
    else:
        names = (
            [device_filter] if device_filter else sorted({b.device for b in store.list_backups()})
        )
        if not names:
            console.print("[yellow]No backups yet. Run backup --demo or backup first.[/]")
            sys.exit(1)
        for name in names:
            platform = platform_for_device(ctx.obj["inventory"], name)
            try:
                _meta, text = store.get(name)
            except FileNotFoundError as exc:
                console.print(f"[red]{exc}[/]")
                continue
            platform = platform or infer_platform_from_config(text)
            if not profile.applies_to(platform):
                console.print(f"[dim]skipping {name} (platform {platform or 'unknown'})[/]")
                continue
            findings.extend(compare_to_baseline(name, text, profile, golden))

    console.print(
        Panel(
            f"Baseline [bold]{profile.name}[/] vs {profile.golden_path()}",
            border_style="cyan",
        )
    )
    _print_findings(findings)

    if export_md:
        export_findings_markdown(
            findings, export_md, title=f"Baseline drift report ({profile.name})"
        )
        console.print(f"[green]Wrote[/] {export_md}")
    if export_csv:
        export_findings_csv(findings, export_csv)
        console.print(f"[green]Wrote[/] {export_csv}")

    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        sys.exit(2)


@main.command("compliance")
@click.option("--device", "device_filter", default=None, help="Limit to one device")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True))
@click.option(
    "--baseline",
    "profile_path",
    default=None,
    type=click.Path(exists=True),
    help="Also count golden config drift from this profile",
)
@click.option("--export", "export_md", default=None, type=click.Path(), help="Markdown report")
@click.option("--csv", "export_csv", default=None, type=click.Path(), help="CSV of scores")
@click.option(
    "--history",
    "history_path",
    default="reports/compliance-history.json",
    show_default=True,
    type=click.Path(),
    help="Score history file (enables the trend column)",
)
@click.option("--no-history", is_flag=True, help="Do not read or write the history file")
@click.option(
    "--min-score",
    default=None,
    type=int,
    help="Exit with code 2 when any device scores below this",
)
@click.pass_context
def compliance_cmd(
    ctx: click.Context,
    device_filter: str | None,
    rules_path: str | None,
    profile_path: str | None,
    export_md: str | None,
    export_csv: str | None,
    history_path: str,
    no_history: bool,
    min_score: int | None,
) -> None:
    """Score each device and map findings to CIS / IEC 62443 controls."""
    store = _store(ctx)
    names = [device_filter] if device_filter else sorted({b.device for b in store.list_backups()})
    if not names:
        console.print("[yellow]No backups yet. Run backup --demo or backup first.[/]")
        sys.exit(1)

    findings = _audit_devices(
        ctx, store, names, rules_path, None, load_firmware_policy(None)
    )

    if profile_path:
        profile = BaselineProfile.load(profile_path)
        try:
            golden = profile.golden_config()
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/]")
            sys.exit(1)
        for name in names:
            _meta, text = store.get(name)
            platform = platform_for_device(ctx.obj["inventory"], name) or infer_platform_from_config(
                text
            )
            if profile.applies_to(platform):
                findings.extend(compare_to_baseline(name, text, profile, golden))

    scores = score_findings(findings)
    for name in names:  # devices with zero findings still deserve a score
        if not any(s.device == name for s in scores):
            scores.append(score_device(name, []))
    scores.sort(key=lambda s: (s.score, s.device))

    history = [] if no_history else load_history(history_path)
    attach_previous(scores, history)

    table = Table(title="Compliance score")
    table.add_column("Device")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Trend", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Medium", justify="right")
    table.add_column("Low", justify="right")
    for score in scores:
        if score.delta is None:
            trend_cell = "[dim]new[/]"
        elif score.delta > 0:
            trend_cell = f"[green]+{score.delta}[/]"
        elif score.delta < 0:
            trend_cell = f"[red]{score.delta}[/]"
        else:
            trend_cell = "[dim]0[/]"
        table.add_row(
            score.device,
            str(score.score),
            score.grade,
            trend_cell,
            str(score.counts.get("critical", 0)),
            str(score.counts.get("high", 0)),
            str(score.counts.get("medium", 0)),
            str(score.counts.get("low", 0)),
        )
    console.print(table)
    console.print(f"Overall: [bold]{overall_score(scores)}/100[/]")

    mapping = load_framework_map()
    controls = control_rollup(findings, mapping)
    control_table = Table(title="Open findings by control (indicative mapping)")
    control_table.add_column("Framework")
    control_table.add_column("Control")
    control_table.add_column("Worst")
    control_table.add_column("Findings", justify="right")
    control_table.add_column("Devices")
    for control in controls:
        control_table.add_row(
            control.framework,
            control.control,
            f"[{SEVERITY_STYLE.get(control.worst.value, '')}]{control.worst.value}[/]",
            str(control.findings),
            ", ".join(control.devices),
        )
    console.print(control_table)

    gaps = unmapped_rules(findings, mapping)
    if gaps:
        console.print(f"[dim]Rules without framework mapping: {', '.join(gaps)}[/]")

    if not no_history:
        record_history(scores, history_path)
        console.print(f"[dim]Score history: {history_path}[/]")

    if export_md:
        export_compliance_markdown(
            scores,
            controls,
            export_md,
            findings=findings,
            history=history,
            unmapped=gaps,
        )
        console.print(f"[green]Wrote[/] {export_md}")
    if export_csv:
        export_compliance_csv(scores, export_csv)
        console.print(f"[green]Wrote[/] {export_csv}")

    if min_score is not None:
        below = [s.device for s in scores if s.score < min_score]
        if below:
            console.print(f"[red]Below the {min_score} point threshold:[/] {', '.join(below)}")
            sys.exit(2)


@main.command("facts")
@click.option("--device", "device_filter", default=None, help="One device (latest backup)")
@click.option("--file", "config_file", default=None, type=click.Path(exists=True))
@click.option("--platform", "platform_override", default=None, help="Force platform")
@click.option("--json", "json_path", default=None, type=click.Path(), help="Write facts as JSON")
@click.pass_context
def facts_cmd(
    ctx: click.Context,
    device_filter: str | None,
    config_file: str | None,
    platform_override: str | None,
    json_path: str | None,
) -> None:
    """Show model, firmware, VLANs, interfaces and admins per device."""
    store = _store(ctx)
    collected: list[DeviceFacts] = []

    if config_file:
        name = Path(config_file).stem
        text = Path(config_file).read_text(encoding="utf-8")
        platform = platform_override or infer_platform_from_config(text)
        collected.append(extract_facts(name, text, platform))
    else:
        names = [device_filter] if device_filter else sorted({b.device for b in store.list_backups()})
        if not names:
            console.print("[yellow]No backups yet. Run backup --demo or backup first.[/]")
            sys.exit(1)
        for name in names:
            try:
                _meta, text = store.get(name)
            except FileNotFoundError as exc:
                console.print(f"[red]{exc}[/]")
                continue
            platform = (
                platform_override
                or platform_for_device(ctx.obj["inventory"], name)
                or infer_platform_from_config(text)
            )
            collected.append(extract_facts(name, text, platform))

    console.print(_facts_table(collected))

    unknown = [f.device for f in collected if not f.firmware]
    if unknown:
        console.print(
            f"[yellow]Firmware unknown for:[/] {', '.join(unknown)} "
            "(capture the version banner in the snapshot to audit patch level)"
        )

    if json_path:
        p = Path(json_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps([f.to_dict() for f in collected], indent=2), encoding="utf-8"
        )
        console.print(f"[green]Wrote[/] {json_path}")


@main.command("wazuh-samples")
@click.option(
    "--file",
    "config_file",
    default="samples/fg-120g-01.cfg",
    show_default=True,
    type=click.Path(exists=True),
    help="Config used to generate representative findings",
)
@click.option("--platform", "platform_override", default=None, help="Force platform")
@click.option(
    "--out",
    default="integrations/wazuh/logtest/samples.log",
    show_default=True,
    type=click.Path(),
    help="Where to write syslog-framed sample lines",
)
@click.option("--limit", default=5, show_default=True, type=int, help="Max finding events")
def wazuh_samples_cmd(
    config_file: str,
    platform_override: str | None,
    out: str,
    limit: int,
) -> None:
    """Generate wazuh-logtest sample lines (syslog framing) from a config."""
    from netaudit.wazuh_integration import operational_event

    text = Path(config_file).read_text(encoding="utf-8")
    platform = platform_override or infer_platform_from_config(text)
    rules = load_rules(platform=platform)
    findings = audit_config(Path(config_file).stem, text, rules, platform=platform)[:limit]

    events = [finding_to_wazuh_event(f) for f in findings]
    events.append(
        operational_event(
            "backup_failed",
            device=Path(config_file).stem,
            severity="high",
            detail=f"Config backup failed for {Path(config_file).stem}: timed out",
            attempts=3,
        )
    )
    events.append(
        operational_event(
            "config_changed",
            device=Path(config_file).stem,
            severity="medium",
            detail=f"Configuration changed on {Path(config_file).stem}",
            platform=platform or "unknown",
        )
    )
    events.append(
        operational_event(
            "run_summary",
            severity="high",
            detail="Backup run finished: 2 ok, 1 changed, 1 failed",
            devices=3,
            ok=2,
            changed=1,
            failed=1,
        )
    )

    lines = [format_syslog_line(event, hostname="netaudit-host") for event in events]
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[green]Wrote[/] {p} ({len(lines)} sample line(s))")
    console.print("[dim]Feed it to the manager: integrations/wazuh/logtest/run-logtest.sh[/]")


@main.command("show")
@click.argument("device")
@click.option("--timestamp", default=None)
@click.pass_context
def show_cmd(ctx: click.Context, device: str, timestamp: str | None) -> None:
    """Print a stored config."""
    store = _store(ctx)
    try:
        meta, text = store.get(device, timestamp)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)
    console.print(f"[dim]{meta.path} | {meta.timestamp} | {meta.sha256[:12]}...[/]")
    console.print(text)


@main.command("import-config")
@click.argument("device")
@click.argument("path", type=click.Path(exists=True))
@click.pass_context
def import_cmd(ctx: click.Context, device: str, path: str) -> None:
    """Import a local config file as a backup snapshot."""
    store = _store(ctx)
    meta = store.import_file(device, path, source="file")
    console.print(f"[green]Imported[/] {device} -> {meta.path}")


if __name__ == "__main__":
    main()
