"""Tests for the Wazuh event format, syslog framing, and rule/decoder assets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree

import pytest

from netaudit.audit import audit_config, load_rules
from netaudit.models import Finding, Severity
from netaudit.runner import _host_key_event
from netaudit.ssh_backup import HostKeyEvent
from netaudit.wazuh_integration import (
    SEVERITY_TO_LEVEL,
    export_wazuh_events_ndjson,
    export_wazuh_ndjson,
    finding_to_wazuh_event,
    format_syslog_line,
    operational_event,
)

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"
WAZUH = REPO / "integrations" / "wazuh"
RULES_XML = WAZUH / "rules" / "netaudit_rules.xml"
TRIGGERS_XML = WAZUH / "rules" / "netaudit_triggers.xml"
DECODER_XML = WAZUH / "decoders" / "netaudit_decoders.xml"

# <134>Jul 25 17:30:00 host netaudit: {...}
SYSLOG_RE = re.compile(r"^<134>[A-Z][a-z]{2} [\d ]\d \d{2}:\d{2}:\d{2} \S+ netaudit: \{")


def _finding(severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        rule_id="FG-POLICY-ANY-ANY",
        title="FortiGate firewall policy accepts all to all",
        severity=severity,
        device="fg-120g-01",
        detail="Policy 'allow-all-any-any' accepts src/dst all",
        line=31,
        evidence="edit 1",
        remediation="Use least-privilege policies.",
    )


def test_finding_event_shape():
    event = finding_to_wazuh_event(_finding())
    assert event["integration"] == "netaudit"
    payload = event["netaudit"]
    assert payload["event_type"] == "finding"
    assert payload["severity"] == "critical"
    assert payload["wazuh_level"] == SEVERITY_TO_LEVEL["critical"]
    assert payload["device"] == "fg-120g-01"


def test_operational_event_shape():
    event = operational_event(
        "backup_failed",
        device="scalance-xc208-01",
        severity="high",
        detail="Config backup failed",
        attempts=3,
    )
    payload = event["netaudit"]
    assert payload["event_type"] == "backup_failed"
    assert payload["rule_id"] == "NETAUDIT-BACKUP-FAILED"
    assert payload["attempts"] == 3
    assert payload["wazuh_level"] == 10


def test_syslog_line_is_rfc3164_framed():
    line = format_syslog_line(finding_to_wazuh_event(_finding()), hostname="netaudit-host")
    assert SYSLOG_RE.match(line), line
    body = line.split("netaudit: ", 1)[1]
    payload = json.loads(body)
    assert payload["netaudit"]["rule_id"] == "FG-POLICY-ANY-ANY"


def test_syslog_line_is_single_line():
    line = format_syslog_line(finding_to_wazuh_event(_finding()))
    assert "\n" not in line


def test_ndjson_append_and_overwrite(tmp_path: Path):
    path = tmp_path / "events.json"
    export_wazuh_ndjson([_finding()], path, append=False)
    export_wazuh_ndjson([_finding(Severity.HIGH)], path, append=True)
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    export_wazuh_events_ndjson([operational_event("run_summary")], path, append=False)
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 1


def test_every_severity_maps_to_a_level():
    for severity in Severity:
        event = finding_to_wazuh_event(_finding(severity))
        assert event["netaudit"]["wazuh_level"] >= 3


def test_decoder_xml_is_valid_and_uses_json_plugin():
    root = ElementTree.fromstring(
        f"<root>{DECODER_XML.read_text(encoding='utf-8')}</root>"
    )
    decoders = root.findall("decoder")
    assert [d.get("name") for d in decoders] == ["netaudit"]
    assert decoders[0].findtext("plugin_decoder") == "JSON_Decoder"
    assert decoders[0].findtext("program_name") == "^netaudit$"


def test_agent_snippet_is_valid_xml():
    snippet = (WAZUH / "ossec-localfile.conf.snippet").read_text(encoding="utf-8")
    root = ElementTree.fromstring(f"<root>{snippet}</root>")
    localfiles = root.findall("./ossec_config/localfile")
    assert localfiles
    assert all(lf.findtext("log_format") == "json" for lf in localfiles)


def test_rules_xml_is_valid_and_covers_expected_ids():
    root = ElementTree.fromstring(RULES_XML.read_text(encoding="utf-8"))
    assert root.tag == "group"
    ids = {rule.get("id") for rule in root.findall("rule")}
    expected = {
        "100500",
        "100501",
        "100510",
        "100511",
        "100512",
        "100513",
        "100520",
        "100521",
        "100522",
        "100530",
        "100531",
        "100532",
        "100533",
        "100540",
        "100550",
        "100551",
        "100552",
        "100560",
        "100561",
        "100570",
        "100571",
    }
    assert expected <= ids
    # Rule IDs must stay inside the Wazuh user range
    assert all(int(rule_id) >= 100000 for rule_id in ids)


def test_host_key_change_is_the_highest_rated_rule():
    root = ElementTree.fromstring(RULES_XML.read_text(encoding="utf-8"))
    levels = {rule.get("id"): int(rule.get("level", "0")) for rule in root.findall("rule")}
    assert levels["100550"] == max(levels.values())
    assert levels["100550"] > levels["100510"]  # above a critical finding


def test_trigger_rules_are_valid_and_do_not_clash():
    root = ElementTree.fromstring(TRIGGERS_XML.read_text(encoding="utf-8"))
    assert root.tag == "group"
    trigger_ids = {rule.get("id") for rule in root.findall("rule")}
    assert {"100580", "100581", "100582"} <= trigger_ids

    netaudit_ids = {
        rule.get("id")
        for rule in ElementTree.fromstring(RULES_XML.read_text(encoding="utf-8")).findall("rule")
    }
    assert not trigger_ids & netaudit_ids


def test_active_response_snippet_is_valid_and_wired_to_real_rules():
    snippet = (WAZUH / "active-response" / "ossec.conf.snippet").read_text(encoding="utf-8")
    root = ElementTree.fromstring(f"<root>{snippet}</root>")

    command = root.find("command")
    assert command is not None
    assert command.findtext("name") == "netaudit-respond"
    assert command.findtext("executable") == "netaudit-ar.py"

    response = root.find("active-response")
    assert response is not None
    assert response.findtext("command") == "netaudit-respond"

    wired = {rid.strip() for rid in (response.findtext("rules_id") or "").split(",")}
    known = {
        rule.get("id")
        for xml in (RULES_XML, TRIGGERS_XML)
        for rule in ElementTree.fromstring(xml.read_text(encoding="utf-8")).findall("rule")
    }
    assert wired <= known, f"active response references unknown rules: {wired - known}"
    # Triggering on netaudit's own config_changed rule would chase its own tail
    assert "100531" not in wired


def _all_event_fields() -> set[str]:
    """Every key netaudit can put in an event payload, for rule validation."""
    fields = set(finding_to_wazuh_event(_finding())["netaudit"].keys())
    fields |= set(
        operational_event("run_summary", failed=1, ok=2, changed=1, devices=3)["netaudit"].keys()
    )
    fields |= set(
        operational_event("backup_failed", attempts=3, error="x", platform="fortigate")[
            "netaudit"
        ].keys()
    )
    fields |= set(
        _host_key_event(
            HostKeyEvent(
                device="fg-120g-01",
                target="192.168.10.1",
                fingerprint="SHA256:new",
                status="mismatch",
                expected="SHA256:old",
            )
        )["netaudit"].keys()
    )
    fields |= set(
        operational_event(
            "respond_summary",
            device="fg-120g-01",
            triggered_by="wazuh rule 100580",
            agent="fw-edge",
            changed=True,
            findings_total=3,
            findings_serious=1,
        )["netaudit"].keys()
    )
    fields |= set(
        operational_event(
            "config_changed",
            device="fg-120g-01",
            added_lines=2,
            removed_lines=1,
            added_sample=["set x"],
            removed_sample=["set y"],
        )["netaudit"].keys()
    )
    return fields


def test_rules_reference_fields_that_events_actually_contain():
    root = ElementTree.fromstring(RULES_XML.read_text(encoding="utf-8"))
    referenced = {
        field.get("name")
        for rule in root.findall("rule")
        for field in rule.findall("field")
        if (field.get("name") or "").startswith("netaudit.")
    }
    missing = {f.split(".", 1)[1] for f in referenced} - _all_event_fields()
    assert not missing, f"rules reference unknown fields: {missing}"


def test_rule_descriptions_only_interpolate_known_fields():
    root = ElementTree.fromstring(RULES_XML.read_text(encoding="utf-8"))
    known = _all_event_fields()
    for rule in root.findall("rule"):
        description = rule.findtext("description") or ""
        for ref in re.findall(r"\$\(netaudit\.([a-z_]+)\)", description):
            assert ref in known, f"rule {rule.get('id')} references netaudit.{ref}"


def test_logtest_samples_match_syslog_format():
    samples = WAZUH / "logtest" / "samples.log"
    if not samples.exists():
        pytest.skip("samples.log not generated yet (netaudit wazuh-samples)")
    lines = [ln for ln in samples.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines
    for line in lines:
        assert SYSLOG_RE.match(line), line
        json.loads(line.split("netaudit: ", 1)[1])


def test_fortigate_findings_produce_critical_events():
    text = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")
    rules = load_rules(platform="fortigate")
    findings = audit_config("fg-120g-01", text, rules, platform="fortigate")
    events = [finding_to_wazuh_event(f) for f in findings]
    assert any(e["netaudit"]["wazuh_level"] == 12 for e in events)
