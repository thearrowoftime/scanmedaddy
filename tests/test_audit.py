"""Unit tests for audit, diff, store, export, wazuh, platforms."""

from __future__ import annotations

import json
from pathlib import Path

from netaudit.audit import audit_config, infer_platform_from_config, load_rules, summarize_findings
from netaudit.diff import diff_texts
from netaudit.export import export_findings_csv, export_findings_markdown
from netaudit.store import ConfigStore
from netaudit.wazuh_integration import export_wazuh_ndjson, finding_to_wazuh_event

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_audit_detects_permit_any():
    rules = load_rules(platform="cisco_ios")
    cfg = "ip access-list extended X\n permit ip any any\n"
    findings = audit_config("lab", cfg, rules, platform="cisco_ios")
    ids = {f.rule_id for f in findings}
    assert "ACL-PERMIT-ANY" in ids or "ACL-PERMIT-ANY-EXTENDED" in ids


def test_audit_detects_weak_snmp():
    rules = load_rules(platform="cisco_ios")
    cfg = "snmp-server community public RO\n"
    findings = audit_config("lab", cfg, rules, platform="cisco_ios")
    assert any(f.rule_id == "SNMP-WEAK-COMMUNITY" for f in findings)


def test_audit_missing_ntp_syslog():
    rules = load_rules(platform="cisco_ios")
    cfg = "hostname bare\n!\nend\n"
    findings = audit_config("lab", cfg, rules, platform="cisco_ios")
    ids = {f.rule_id for f in findings}
    assert "NTP-MISSING" in ids
    assert "SYSLOG-MISSING" in ids


def test_audit_sample_insecure():
    rules = load_rules(platform="cisco_ios")
    text = (SAMPLES / "core-sw-01.cfg").read_text(encoding="utf-8")
    findings = audit_config("core-sw-01", text, rules, platform="cisco_ios")
    summary = summarize_findings(findings)
    assert summary["critical"] >= 1
    assert summary["high"] >= 1
    ids = {f.rule_id for f in findings}
    assert "ACL-PERMIT-ANY" in ids or "ACL-PERMIT-ANY-EXTENDED" in ids
    assert "SNMP-WEAK-COMMUNITY" in ids
    assert "NTP-MISSING" in ids
    assert "SYSLOG-MISSING" in ids


def test_audit_sample_hardened_cleaner():
    rules = load_rules(platform="cisco_ios")
    bad = audit_config(
        "bad", (SAMPLES / "core-sw-01.cfg").read_text(encoding="utf-8"), rules, platform="cisco_ios"
    )
    good = audit_config(
        "good",
        (SAMPLES / "edge-rtr-01.cfg").read_text(encoding="utf-8"),
        rules,
        platform="cisco_ios",
    )
    assert summarize_findings(good)["critical"] < summarize_findings(bad)["critical"]
    assert summarize_findings(good)["total"] < summarize_findings(bad)["total"]


def test_fortigate_120g_sample():
    text = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")
    assert infer_platform_from_config(text) == "fortigate"
    rules = load_rules(platform="fortigate")
    findings = audit_config("fg-120g-01", text, rules, platform="fortigate")
    ids = {f.rule_id for f in findings}
    assert "FG-POLICY-ANY-ANY" in ids
    assert "FG-SNMP-WEAK" in ids
    assert "FG-NTP-MISSING" in ids
    assert "FG-SYSLOG-MISSING" in ids
    assert "FG-TELNET-ADMIN" in ids
    assert summarize_findings(findings)["critical"] >= 1


def test_scalance_xc208_sample():
    text = (SAMPLES / "scalance-xc208-01.cfg").read_text(encoding="utf-8")
    rules = load_rules(platform="scalance_xc")
    findings = audit_config("scalance-xc208-01", text, rules, platform="scalance_xc")
    ids = {f.rule_id for f in findings}
    assert "SC-ACL-PERMIT-ANY" in ids
    assert "SC-SNMP-WEAK" in ids
    assert "SC-NTP-MISSING" in ids
    assert "SC-SYSLOG-MISSING" in ids
    assert "SC-TELNET-ENABLED" in ids


def test_cisco_rules_do_not_apply_to_fortigate():
    text = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")
    rules = load_rules(platform="fortigate")
    findings = audit_config("fg", text, rules, platform="fortigate")
    assert not any(f.rule_id.startswith("ACL-") for f in findings)
    assert not any(f.rule_id == "NTP-MISSING" for f in findings)


def test_diff_detects_changes():
    old = "hostname a\nntp server 1.1.1.1\n"
    new = "hostname a\nntp server 1.1.1.1\nlogging host 2.2.2.2\n"
    result = diff_texts("dev", "t1", "t2", old, new)
    assert result.has_changes
    assert any("logging host" in ln for ln in result.added)


def test_store_versions(tmp_path: Path):
    store = ConfigStore(tmp_path / "backups")
    m1 = store.save("sw1", "hostname sw1\n", source="demo")
    m2 = store.save("sw1", "hostname sw1\nntp server 1.2.3.4\n", source="demo")
    assert m1.sha256 != m2.sha256
    assert len(store.list_backups("sw1")) == 2
    m3 = store.save("sw1", "hostname sw1\nntp server 1.2.3.4\n", source="demo")
    assert m3.timestamp == m2.timestamp
    assert len(store.list_backups("sw1")) == 2


def test_export(tmp_path: Path):
    rules = load_rules(platform="cisco_ios")
    text = (SAMPLES / "core-sw-01.cfg").read_text(encoding="utf-8")
    findings = audit_config("core-sw-01", text, rules, platform="cisco_ios")
    md = export_findings_markdown(findings, tmp_path / "report.md")
    csv = export_findings_csv(findings, tmp_path / "report.csv")
    assert "ACL" in md.read_text(encoding="utf-8") or "permit" in md.read_text(encoding="utf-8").lower()
    assert csv.read_text(encoding="utf-8").splitlines()[0].startswith("device")


def test_wazuh_ndjson(tmp_path: Path):
    rules = load_rules(platform="fortigate")
    text = (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8")
    findings = audit_config("fg-120g-01", text, rules, platform="fortigate")
    out = export_wazuh_ndjson(findings, tmp_path / "wazuh.json", append=False)
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(findings)
    event = json.loads(lines[0])
    assert event["integration"] == "netaudit"
    assert "netaudit" in event
    assert event["netaudit"]["device"] == "fg-120g-01"
    sample = finding_to_wazuh_event(findings[0])
    assert sample["netaudit"]["wazuh_level"] >= 3
