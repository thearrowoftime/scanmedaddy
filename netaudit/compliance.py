"""Compliance scoring and control framework rollup.

A raw finding list answers "what is wrong". Management asks two other
questions: how bad is it overall, and which control does it break. This module
turns findings into a score per device, tracks that score over time, and groups
findings by CIS Controls v8 safeguards and IEC 62443-3-3 system requirements.

The framework mapping is indicative - useful to steer remediation and to talk to
auditors - not a certification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from netaudit.models import Finding, Severity

FRAMEWORK_FILE = "frameworks.yaml"

# Points deducted from 100 per finding, by severity
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


@dataclass
class DeviceScore:
    device: str
    score: int
    counts: dict[str, int] = field(default_factory=dict)
    total: int = 0
    previous: int | None = None

    @property
    def delta(self) -> int | None:
        return None if self.previous is None else self.score - self.previous

    @property
    def grade(self) -> str:
        if self.score >= 90:
            return "A"
        if self.score >= 75:
            return "B"
        if self.score >= 60:
            return "C"
        if self.score >= 40:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "score": self.score,
            "grade": self.grade,
            "total": self.total,
            "counts": self.counts,
        }


@dataclass
class ControlStatus:
    framework: str
    control: str
    findings: int
    devices: list[str]
    worst: Severity
    rules: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "control": self.control,
            "findings": self.findings,
            "devices": self.devices,
            "worst_severity": self.worst.value,
            "rules": self.rules,
        }


def _empty_counts() -> dict[str, int]:
    return {s.value: 0 for s in Severity}


def score_device(device: str, findings: list[Finding]) -> DeviceScore:
    counts = _empty_counts()
    penalty = 0
    for finding in findings:
        counts[finding.severity.value] += 1
        penalty += SEVERITY_WEIGHTS.get(finding.severity, 0)
    return DeviceScore(
        device=device,
        score=max(0, 100 - penalty),
        counts=counts,
        total=len(findings),
    )


def score_findings(findings: list[Finding]) -> list[DeviceScore]:
    """One score per device, worst first."""
    by_device: dict[str, list[Finding]] = {}
    for finding in findings:
        by_device.setdefault(finding.device, []).append(finding)
    scores = [score_device(device, items) for device, items in by_device.items()]
    scores.sort(key=lambda s: (s.score, s.device))
    return scores


def overall_score(scores: list[DeviceScore]) -> int:
    if not scores:
        return 100
    return round(sum(s.score for s in scores) / len(scores))


def load_framework_map(path: str | Path | None = None) -> dict[str, dict[str, list[str]]]:
    """rule_id -> {framework: [control, ...]}"""
    if path:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    else:
        try:
            text = (resources.files("netaudit.rules") / FRAMEWORK_FILE).read_text(encoding="utf-8")
        except (FileNotFoundError, TypeError, AttributeError):
            text = (Path(__file__).parent / "rules" / FRAMEWORK_FILE).read_text(encoding="utf-8")
        raw = yaml.safe_load(text) or {}

    mappings = raw.get("mappings") or {}
    normalized: dict[str, dict[str, list[str]]] = {}
    for rule_id, frameworks in mappings.items():
        normalized[rule_id] = {
            framework: [str(c) for c in (controls or [])]
            for framework, controls in (frameworks or {}).items()
        }
    return normalized


def control_rollup(
    findings: list[Finding],
    mapping: dict[str, dict[str, list[str]]] | None = None,
) -> list[ControlStatus]:
    """Group findings by framework control, worst severity first."""
    mapping = mapping if mapping is not None else load_framework_map()
    buckets: dict[tuple[str, str], dict[str, Any]] = {}

    for finding in findings:
        frameworks = mapping.get(finding.rule_id)
        if not frameworks:
            continue
        for framework, controls in frameworks.items():
            for control in controls:
                bucket = buckets.setdefault(
                    (framework, control),
                    {"findings": 0, "devices": [], "rules": [], "worst": Severity.INFO},
                )
                bucket["findings"] += 1
                if finding.device not in bucket["devices"]:
                    bucket["devices"].append(finding.device)
                if finding.rule_id not in bucket["rules"]:
                    bucket["rules"].append(finding.rule_id)
                if SEVERITY_ORDER.index(finding.severity) < SEVERITY_ORDER.index(bucket["worst"]):
                    bucket["worst"] = finding.severity

    statuses = [
        ControlStatus(
            framework=framework,
            control=control,
            findings=data["findings"],
            devices=sorted(data["devices"]),
            worst=data["worst"],
            rules=sorted(data["rules"]),
        )
        for (framework, control), data in buckets.items()
    ]
    statuses.sort(key=lambda s: (s.framework, SEVERITY_ORDER.index(s.worst), s.control))
    return statuses


def unmapped_rules(
    findings: list[Finding],
    mapping: dict[str, dict[str, list[str]]] | None = None,
) -> list[str]:
    """Rule ids without a framework mapping, so gaps stay visible."""
    mapping = mapping if mapping is not None else load_framework_map()
    return sorted({f.rule_id for f in findings if f.rule_id not in mapping})


def load_history(path: str | Path) -> list[dict[str, Any]]:
    history_path = Path(path)
    if not history_path.exists():
        return []
    try:
        data = json.loads(history_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def attach_previous(scores: list[DeviceScore], history: list[dict[str, Any]]) -> list[DeviceScore]:
    """Fill in each device's last recorded score so the trend can be shown."""
    last: dict[str, int] = {}
    for entry in history:
        for device_entry in entry.get("devices", []):
            device = device_entry.get("device")
            if device is not None:
                last[device] = int(device_entry.get("score", 0))
    for score in scores:
        score.previous = last.get(score.device)
    return scores


def record_history(
    scores: list[DeviceScore],
    path: str | Path,
    *,
    keep: int = 200,
) -> dict[str, Any]:
    """Append this run to the history file and return the stored entry."""
    history_path = Path(path)
    history = load_history(history_path)
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall": overall_score(scores),
        "devices": [s.to_dict() for s in scores],
    }
    history.append(entry)
    history = history[-keep:]
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    return entry


def trend(history: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    """Recent overall scores as (timestamp, score) pairs."""
    return [(e.get("timestamp", ""), int(e.get("overall", 0))) for e in history[-limit:]]
