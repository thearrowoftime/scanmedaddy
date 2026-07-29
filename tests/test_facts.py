"""Inventory facts and firmware policy tests."""

from __future__ import annotations

from pathlib import Path

from netaudit.facts import (
    DeviceFacts,
    extract_facts,
    facts_findings,
    firmware_findings,
    load_firmware_policy,
    version_tuple,
)
from netaudit.models import Severity

SAMPLES = Path(__file__).parent.parent / "samples"


def _sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def test_fortigate_facts_from_config_version_header():
    facts = extract_facts("fg-120g-01", _sample("fg-120g-01.cfg"), "fortigate")

    assert facts.model == "FG120G"
    assert facts.firmware == "7.0.12"
    assert facts.build == "0523"
    assert facts.serial == "FG120G1234567890"
    assert facts.hostname == "fg-120g-01"
    assert facts.interfaces == ["port1"]
    assert facts.admins == ["admin"]
    assert facts.mgmt_addresses == ["192.168.10.1"]
    assert facts.firmware_label == "7.0.12 (build 0523)"


def test_scalance_facts_from_header_comment():
    facts = extract_facts("scalance-xc208-01", _sample("scalance-xc208-01.cfg"), "scalance_xc")

    assert facts.model == "SCALANCE XC208"
    assert facts.firmware == "04.02.00"
    assert facts.hostname == "scalance-xc208-01"
    assert facts.vlans == ["1", "30"]
    assert facts.interfaces == ["vlan 1", "vlan 30"]
    assert facts.admins == ["admin"]


def test_cisco_facts():
    config = """\
hostname core-sw-01
version 15.2
username netops privilege 15 secret 5 hash
vlan 10
vlan 20
interface Vlan10
 ip address 10.0.0.1 255.255.255.0
"""
    facts = extract_facts("core-sw-01", config, "cisco_ios")

    assert facts.hostname == "core-sw-01"
    assert facts.firmware == "15.2"
    assert facts.vlans == ["10", "20"]
    assert facts.interfaces == ["Vlan10"]
    assert facts.admins == ["netops"]
    assert facts.mgmt_addresses == ["10.0.0.1"]


def test_hostname_falls_back_to_device_name():
    facts = extract_facts("unnamed-01", "snmp-server community public RO\n", "scalance_xc")
    assert facts.hostname == "unnamed-01"


def test_version_tuple_normalises_vendor_formats():
    assert version_tuple("V04.05.00") == (4, 5, 0)
    assert version_tuple("7.2.9") == (7, 2, 9)
    assert version_tuple("15.2(4)S") == (15, 2, 4)
    assert version_tuple("") == ()
    # padded and unpadded forms compare correctly
    assert version_tuple("04.02.00") < version_tuple("4.5")


def test_outdated_firmware_is_reported():
    facts = extract_facts("fg-120g-01", _sample("fg-120g-01.cfg"), "fortigate")
    findings = firmware_findings(facts)

    assert len(findings) == 1
    assert findings[0].rule_id == "FW-OUTDATED"
    assert findings[0].severity == Severity.HIGH
    assert "7.2.9" in findings[0].remediation
    assert "PSIRT" in findings[0].remediation


def test_current_firmware_is_clean():
    facts = DeviceFacts(device="fg-01", platform="fortigate", firmware="7.4.5")
    assert firmware_findings(facts) == []


def test_unknown_firmware_is_low_severity():
    facts = DeviceFacts(device="xc208-01", platform="scalance_xc")
    findings = firmware_findings(facts)

    assert len(findings) == 1
    assert findings[0].rule_id == "FW-UNKNOWN"
    assert findings[0].severity == Severity.LOW


def test_platform_without_policy_is_ignored():
    facts = DeviceFacts(device="misc-01", platform="juniper", firmware="12.1")
    assert firmware_findings(facts) == []


def test_custom_policy_file(tmp_path: Path):
    policy_file = tmp_path / "firmware.yaml"
    policy_file.write_text(
        "minimum:\n  fortigate: '6.0.0'\npolicy:\n  severity: critical\n",
        encoding="utf-8",
    )
    policy = load_firmware_policy(policy_file)

    facts = DeviceFacts(device="fg-01", platform="fortigate", firmware="5.6.1")
    findings = firmware_findings(facts, policy)
    assert findings[0].severity == Severity.CRITICAL

    up_to_date = DeviceFacts(device="fg-02", platform="fortigate", firmware="7.0.12")
    assert firmware_findings(up_to_date, policy) == []


def test_facts_findings_wrapper():
    facts, findings = facts_findings(
        "scalance-xc208-01", _sample("scalance-xc208-01.cfg"), "scalance_xc"
    )
    assert facts.firmware == "04.02.00"
    assert [f.rule_id for f in findings] == ["FW-OUTDATED"]
