"""Export audit findings and diffs to CSV / Markdown."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from netaudit.audit import summarize_findings
from netaudit.compliance import ControlStatus, DeviceScore, overall_score, trend
from netaudit.diff import DiffResult, format_diff_markdown
from netaudit.models import Finding


def export_findings_csv(findings: list[Finding], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "device",
        "severity",
        "rule_id",
        "title",
        "line",
        "detail",
        "evidence",
        "remediation",
    ]
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            row = f.to_dict()
            writer.writerow({k: row.get(k, "") for k in fieldnames})
    return p


def export_findings_markdown(
    findings: list[Finding],
    path: str | Path,
    title: str = "Network Security Audit Report",
) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = summarize_findings(findings)

    lines: list[str] = [
        f"# {title}",
        "",
        f"_Generated: {now}_",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
        f"| critical | {summary['critical']} |",
        f"| high | {summary['high']} |",
        f"| medium | {summary['medium']} |",
        f"| low | {summary['low']} |",
        f"| info | {summary['info']} |",
        f"| **total** | **{summary['total']}** |",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No findings — configs passed all enabled rules.")
    else:
        for f in findings:
            loc = f" (line {f.line})" if f.line else ""
            lines.append(f"### [{f.severity.value.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **Device:** `{f.device}`")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Detail:** {f.detail}{loc}")
            if f.evidence:
                lines.append(f"- **Evidence:** `{f.evidence}`")
            if f.remediation:
                lines.append(f"- **Remediation:** {f.remediation}")
            lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def export_compliance_markdown(
    scores: list[DeviceScore],
    controls: list[ControlStatus],
    path: str | Path,
    *,
    findings: list[Finding] | None = None,
    history: list[dict] | None = None,
    unmapped: list[str] | None = None,
) -> Path:
    """Management-facing report: score per device, then control coverage."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# Network Compliance Report",
        "",
        f"_Generated: {now}_",
        "",
        f"**Overall score: {overall_score(scores)}/100**",
        "",
        "## Score per device",
        "",
        "| Device | Score | Grade | Change | Critical | High | Medium | Low |",
        "|--------|------:|:-----:|-------:|---------:|-----:|-------:|----:|",
    ]
    for score in scores:
        delta = "-" if score.delta is None else f"{score.delta:+d}"
        lines.append(
            f"| `{score.device}` | {score.score} | {score.grade} | {delta} | "
            f"{score.counts.get('critical', 0)} | {score.counts.get('high', 0)} | "
            f"{score.counts.get('medium', 0)} | {score.counts.get('low', 0)} |"
        )

    if history:
        lines += ["", "## Trend", "", "| Run | Overall |", "|-----|--------:|"]
        for timestamp, value in trend(history):
            lines.append(f"| {timestamp} | {value} |")

    lines += [
        "",
        "## Control coverage",
        "",
        "Indicative mapping to CIS Controls v8 and IEC 62443-3-3. Controls listed",
        "here have at least one open finding.",
        "",
        "| Framework | Control | Worst | Findings | Devices | Rules |",
        "|-----------|---------|-------|---------:|---------|-------|",
    ]
    if not controls:
        lines.append("| - | no mapped findings | - | 0 | - | - |")
    for control in controls:
        lines.append(
            f"| {control.framework} | {control.control} | {control.worst.value} | "
            f"{control.findings} | {', '.join(f'`{d}`' for d in control.devices)} | "
            f"{', '.join(control.rules)} |"
        )

    if unmapped:
        lines += [
            "",
            "## Unmapped rules",
            "",
            "These rules produced findings but have no framework mapping yet:",
            "",
            ", ".join(f"`{rule}`" for rule in unmapped),
        ]

    if findings:
        summary = summarize_findings(findings)
        lines += [
            "",
            "## Finding totals",
            "",
            f"critical {summary['critical']}, high {summary['high']}, "
            f"medium {summary['medium']}, low {summary['low']}, info {summary['info']} "
            f"(total {summary['total']})",
        ]

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def export_compliance_csv(scores: list[DeviceScore], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "score", "grade", "critical", "high", "medium", "low", "info"])
        for score in scores:
            writer.writerow(
                [
                    score.device,
                    score.score,
                    score.grade,
                    score.counts.get("critical", 0),
                    score.counts.get("high", 0),
                    score.counts.get("medium", 0),
                    score.counts.get("low", 0),
                    score.counts.get("info", 0),
                ]
            )
    return p


def export_diff_markdown(result: DiffResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(format_diff_markdown(result), encoding="utf-8")
    return p


def export_diff_csv(result: DiffResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "side", "line"])
        for ln in result.removed:
            writer.writerow([result.device, "removed", ln])
        for ln in result.added:
            writer.writerow([result.device, "added", ln])
    return p
