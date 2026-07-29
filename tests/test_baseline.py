"""Golden config drift tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from netaudit.baseline import (
    BaselineProfile,
    compare_to_baseline,
    extract_sections,
)
from netaudit.models import Severity

REPO = Path(__file__).parent.parent
BASELINES = REPO / "baselines"
SAMPLES = REPO / "samples"

GOLDEN_FORTIOS = """\
config system global
    set admintimeout 10
    set hostname "fg-golden"
end
config system ntp
    set ntpsync enable
    config ntpserver
        edit 1
            set server "10.10.0.10"
        next
    end
end
"""


def _profile(tmp_path: Path, **overrides) -> BaselineProfile:
    golden = tmp_path / "golden.cfg"
    golden.write_text(overrides.pop("golden_text", GOLDEN_FORTIOS), encoding="utf-8")
    data = {
        "name": "test-profile",
        "golden": str(golden),
        "platforms": ["fortigate"],
        "sections": ["(?i)^config system global\\b", "(?i)^config system ntp\\b"],
        "ignore": ["(?i)^\\s*set\\s+hostname\\b"],
        "severity": Severity.MEDIUM,
        "style": "fortios",
        "path": tmp_path / "profile.yaml",
    }
    data.update(overrides)
    return BaselineProfile(**data)


def test_identical_config_has_no_drift(tmp_path: Path):
    profile = _profile(tmp_path)
    assert compare_to_baseline("fg-01", GOLDEN_FORTIOS, profile) == []


def test_ignored_lines_do_not_count_as_drift(tmp_path: Path):
    profile = _profile(tmp_path)
    changed_hostname = GOLDEN_FORTIOS.replace('"fg-golden"', '"fg-120g-01"')
    assert compare_to_baseline("fg-01", changed_hostname, profile) == []


def test_changed_value_is_reported_as_drift(tmp_path: Path):
    profile = _profile(tmp_path)
    drifted = GOLDEN_FORTIOS.replace("set admintimeout 10", "set admintimeout 480")
    findings = compare_to_baseline("fg-01", drifted, profile)

    assert [f.rule_id for f in findings] == ["BASELINE-DRIFT"]
    assert findings[0].severity == Severity.MEDIUM
    assert "admintimeout" in findings[0].evidence
    assert findings[0].device == "fg-01"


def test_missing_section_is_reported(tmp_path: Path):
    profile = _profile(tmp_path)
    without_ntp = GOLDEN_FORTIOS.split("config system ntp")[0]
    findings = compare_to_baseline("fg-01", without_ntp, profile)

    assert [f.rule_id for f in findings] == ["BASELINE-MISSING"]
    assert "config system ntp" in findings[0].title


def test_section_absent_from_baseline_is_reported(tmp_path: Path):
    profile = _profile(
        tmp_path,
        golden_text="config system global\n    set admintimeout 10\nend\n",
    )
    findings = compare_to_baseline("fg-01", GOLDEN_FORTIOS, profile)

    assert [f.rule_id for f in findings] == ["BASELINE-EXTRA"]


def test_nested_config_blocks_are_kept_together():
    sections = extract_sections(GOLDEN_FORTIOS, ["(?i)^config system ntp\\b"], "fortios")
    block = sections["(?i)^config system ntp\\b"]

    # the nested config ntpserver / end pair must not terminate the block early
    assert block[0].strip() == "config system ntp"
    assert block[-1].strip() == "end"
    assert any("edit 1" in line for line in block)
    assert sum(1 for line in block if line.strip() == "end") == 2


def test_whole_config_mode_without_sections(tmp_path: Path):
    profile = _profile(tmp_path, sections=[])
    drifted = GOLDEN_FORTIOS + "config firewall policy\n    edit 1\n    next\nend\n"
    findings = compare_to_baseline("fg-01", drifted, profile)

    assert [f.rule_id for f in findings] == ["BASELINE-DRIFT"]
    assert "unexpected" in findings[0].detail


def test_indent_style_blocks(tmp_path: Path):
    golden = "line vty 0 4\n access-class MGMT in\n transport input ssh\n login\n!\nend\n"
    profile = _profile(
        tmp_path,
        golden_text=golden,
        sections=["(?i)^line vty\\b"],
        ignore=[],
        style="indent",
        platforms=["scalance_xc"],
    )
    device = "line vty 0 4\n transport input all\n login\n!\nend\n"
    findings = compare_to_baseline("xc208-01", device, profile)

    assert [f.rule_id for f in findings] == ["BASELINE-DRIFT"]
    assert "access-class" in findings[0].evidence


def test_profile_requires_golden_key(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: broken\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing the 'golden' key"):
        BaselineProfile.load(bad)


def test_shipped_profiles_load_and_flag_the_samples():
    """The bundled examples must work against the bundled insecure samples."""
    fortigate = BaselineProfile.load(BASELINES / "fortigate-lab.yaml")
    findings = compare_to_baseline(
        "fg-120g-01",
        (SAMPLES / "fg-120g-01.cfg").read_text(encoding="utf-8"),
        fortigate,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "BASELINE-MISSING" in rule_ids
    assert fortigate.block_style() == "fortios"
    assert fortigate.applies_to("fortios")
    assert not fortigate.applies_to("scalance_xc")

    scalance = BaselineProfile.load(BASELINES / "scalance-lab.yaml")
    drift = compare_to_baseline(
        "scalance-xc208-01",
        (SAMPLES / "scalance-xc208-01.cfg").read_text(encoding="utf-8"),
        scalance,
    )
    assert {f.rule_id for f in drift} == {"BASELINE-MISSING", "BASELINE-DRIFT"}
    assert scalance.block_style() == "indent"


def test_missing_golden_file_raises(tmp_path: Path):
    profile = BaselineProfile(name="x", golden=str(tmp_path / "nope.cfg"))
    with pytest.raises(FileNotFoundError, match="golden config not found"):
        profile.golden_config()
