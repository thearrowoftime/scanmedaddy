"""Compliance scoring, framework rollup and history tests."""

from __future__ import annotations

import json
from pathlib import Path

from netaudit.compliance import (
    SEVERITY_WEIGHTS,
    attach_previous,
    control_rollup,
    load_framework_map,
    load_history,
    overall_score,
    record_history,
    score_device,
    score_findings,
    trend,
    unmapped_rules,
)
from netaudit.models import Finding, Severity


def _finding(rule_id: str, severity: Severity, device: str = "fg-01") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        device=device,
        detail="",
    )


def test_clean_device_scores_100():
    score = score_device("fg-01", [])
    assert score.score == 100
    assert score.grade == "A"
    assert score.total == 0


def test_score_deducts_by_severity():
    findings = [
        _finding("FG-POLICY-ANY-ANY", Severity.CRITICAL),
        _finding("FG-TELNET-ADMIN", Severity.HIGH),
        _finding("FG-NTP-MISSING", Severity.MEDIUM),
    ]
    expected = 100 - (
        SEVERITY_WEIGHTS[Severity.CRITICAL]
        + SEVERITY_WEIGHTS[Severity.HIGH]
        + SEVERITY_WEIGHTS[Severity.MEDIUM]
    )
    score = score_device("fg-01", findings)

    assert score.score == expected
    assert score.total == 3
    assert score.counts["critical"] == 1


def test_info_findings_do_not_reduce_the_score():
    assert score_device("fg-01", [_finding("X", Severity.INFO)]).score == 100


def test_score_floors_at_zero():
    findings = [_finding(f"R{i}", Severity.CRITICAL) for i in range(10)]
    assert score_device("fg-01", findings).score == 0


def test_score_findings_sorts_worst_first_and_averages():
    findings = [
        _finding("FG-POLICY-ANY-ANY", Severity.CRITICAL, "fg-01"),
        _finding("SC-NTP-MISSING", Severity.MEDIUM, "xc208-01"),
    ]
    scores = score_findings(findings)

    assert [s.device for s in scores] == ["fg-01", "xc208-01"]
    assert overall_score(scores) == round((75 + 96) / 2)
    assert overall_score([]) == 100


def test_grades_cover_the_range():
    assert score_device("a", []).grade == "A"
    assert score_device("b", [_finding("x", Severity.HIGH)] * 2).grade == "B"
    assert score_device("c", [_finding("x", Severity.HIGH)] * 4).grade == "C"
    assert score_device("d", [_finding("x", Severity.HIGH)] * 6).grade == "D"
    assert score_device("f", [_finding("x", Severity.CRITICAL)] * 3).grade == "F"


def test_framework_rollup_groups_by_control():
    findings = [
        _finding("FG-POLICY-ANY-ANY", Severity.CRITICAL, "fg-01"),
        _finding("SC-ACL-PERMIT-ANY", Severity.CRITICAL, "xc208-01"),
        _finding("FG-NTP-MISSING", Severity.MEDIUM, "fg-01"),
    ]
    controls = control_rollup(findings)
    by_key = {(c.framework, c.control): c for c in controls}

    segmentation = by_key[("cis", "13.4")]
    assert segmentation.findings == 2
    assert segmentation.devices == ["fg-01", "xc208-01"]
    assert segmentation.worst == Severity.CRITICAL

    time_sync = by_key[("cis", "8.4")]
    assert time_sync.worst == Severity.MEDIUM
    assert time_sync.rules == ["FG-NTP-MISSING"]

    assert ("iec62443", "SR 5.1") in by_key
    assert ("iec62443", "SR 2.11") in by_key


def test_rollup_orders_critical_controls_first():
    findings = [
        _finding("FG-NTP-MISSING", Severity.MEDIUM),
        _finding("FG-POLICY-ANY-ANY", Severity.CRITICAL),
    ]
    cis = [c for c in control_rollup(findings) if c.framework == "cis"]
    assert cis[0].worst == Severity.CRITICAL


def test_unmapped_rules_are_reported():
    findings = [
        _finding("FG-POLICY-ANY-ANY", Severity.HIGH),
        _finding("MY-CUSTOM-RULE", Severity.HIGH),
    ]
    assert unmapped_rules(findings) == ["MY-CUSTOM-RULE"]
    assert control_rollup([_finding("MY-CUSTOM-RULE", Severity.HIGH)]) == []


def test_bundled_mapping_covers_baseline_and_firmware_rules():
    mapping = load_framework_map()
    for rule_id in ("BASELINE-DRIFT", "BASELINE-MISSING", "FW-OUTDATED", "FW-UNKNOWN"):
        assert rule_id in mapping
        assert mapping[rule_id]["cis"]
        assert mapping[rule_id]["iec62443"]


def test_custom_mapping_file(tmp_path: Path):
    mapping_file = tmp_path / "frameworks.yaml"
    mapping_file.write_text(
        "mappings:\n  MY-RULE:\n    internal: ['POL-1']\n",
        encoding="utf-8",
    )
    mapping = load_framework_map(mapping_file)
    controls = control_rollup([_finding("MY-RULE", Severity.HIGH)], mapping)

    assert [(c.framework, c.control) for c in controls] == [("internal", "POL-1")]


def test_history_round_trip_and_trend(tmp_path: Path):
    history_file = tmp_path / "compliance-history.json"
    first = [score_device("fg-01", [_finding("x", Severity.CRITICAL)])]
    record_history(first, history_file)

    second = [score_device("fg-01", [])]
    attach_previous(second, load_history(history_file))
    assert second[0].previous == 75
    assert second[0].delta == 25

    record_history(second, history_file)
    history = load_history(history_file)
    assert len(history) == 2
    assert [value for _ts, value in trend(history)] == [75, 100]


def test_history_keeps_only_recent_entries(tmp_path: Path):
    history_file = tmp_path / "history.json"
    for _ in range(5):
        record_history([score_device("fg-01", [])], history_file, keep=3)
    assert len(load_history(history_file)) == 3


def test_corrupt_history_is_ignored(tmp_path: Path):
    history_file = tmp_path / "history.json"
    history_file.write_text("{not json", encoding="utf-8")
    assert load_history(history_file) == []

    record_history([score_device("fg-01", [])], history_file)
    assert isinstance(json.loads(history_file.read_text(encoding="utf-8")), list)


def test_devices_without_previous_score_have_no_delta():
    scores = [score_device("new-device", [])]
    attach_previous(scores, [])
    assert scores[0].previous is None
    assert scores[0].delta is None
