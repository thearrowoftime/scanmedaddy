"""Golden config comparison (baseline drift).

Rules answer "is this device configured securely". A baseline answers a
different question: "does this device still match the configuration we
approved". Only the sections named in the profile are compared, so per-device
values (hostname, addresses, serials) do not show up as drift.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from netaudit.models import Finding, Severity

FORTIOS_PLATFORMS = {"fortigate", "fortios"}
DRIFT_RULE = "BASELINE-DRIFT"
MISSING_RULE = "BASELINE-MISSING"
EXTRA_RULE = "BASELINE-EXTRA"


@dataclass
class BaselineProfile:
    """An approved configuration template plus what to compare against it."""

    name: str
    golden: str
    platforms: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    style: str = ""  # fortios | indent (inferred from platforms when empty)
    path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> BaselineProfile:
        profile_path = Path(path)
        raw: dict[str, Any] = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
        if "golden" not in raw:
            raise ValueError(f"{profile_path}: profile is missing the 'golden' key")
        return cls(
            name=raw.get("name") or profile_path.stem,
            golden=raw["golden"],
            platforms=[p.lower() for p in raw.get("platforms", [])],
            sections=list(raw.get("sections", [])),
            ignore=list(raw.get("ignore", [])),
            severity=Severity(raw.get("severity", "medium")),
            style=(raw.get("style") or "").lower(),
            path=profile_path,
        )

    def applies_to(self, platform: str | None) -> bool:
        if not self.platforms or not platform:
            return True
        return platform.lower() in self.platforms

    def golden_path(self) -> Path:
        golden = Path(self.golden)
        if not golden.is_absolute() and self.path is not None:
            candidate = self.path.parent / golden
            if candidate.exists():
                return candidate
        return golden

    def golden_config(self) -> str:
        path = self.golden_path()
        if not path.exists():
            raise FileNotFoundError(f"golden config not found: {path}")
        return path.read_text(encoding="utf-8")

    def block_style(self) -> str:
        if self.style:
            return self.style
        if any(p in FORTIOS_PLATFORMS for p in self.platforms):
            return "fortios"
        return "indent"


def _normalize(lines: list[str], ignore: list[str]) -> list[str]:
    patterns = [re.compile(p) for p in ignore]
    cleaned: list[str] = []
    for raw in lines:
        line = raw.replace("\t", "    ").rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith(("!", "#")):
            continue
        if any(p.search(line) for p in patterns):
            continue
        cleaned.append(line)
    return cleaned


def _fortios_block(lines: list[str], start: int) -> list[str]:
    """A FortiOS config block, honouring nested config/end pairs."""
    block = [lines[start]]
    depth = 1
    index = start + 1
    while index < len(lines) and depth > 0:
        stripped = lines[index].strip()
        if re.match(r"(?i)^config\b", stripped):
            depth += 1
        elif re.match(r"(?i)^end\b", stripped):
            depth -= 1
            if depth == 0:
                block.append(lines[index])
                break
        block.append(lines[index])
        index += 1
    return block


def _indent_block(lines: list[str], start: int) -> list[str]:
    block = [lines[start]]
    index = start + 1
    while index < len(lines):
        line = lines[index]
        if line.startswith((" ", "\t")):
            block.append(line)
            index += 1
            continue
        if line.strip() == "!":
            break
        break
    return block


def extract_sections(config: str, patterns: list[str], style: str) -> dict[str, list[str]]:
    """Map each section pattern to the block found in the config."""
    lines = config.splitlines()
    compiled = [(p, re.compile(p)) for p in patterns]
    found: dict[str, list[str]] = {}

    for index, line in enumerate(lines):
        for pattern, regex in compiled:
            if pattern in found:
                continue
            if regex.search(line):
                found[pattern] = (
                    _fortios_block(lines, index) if style == "fortios" else _indent_block(lines, index)
                )
    return found


def _diff_counts(golden: list[str], current: list[str]) -> tuple[list[str], list[str]]:
    removed = [ln for ln in difflib.unified_diff(golden, current, n=0) if ln.startswith("-") and not ln.startswith("---")]
    added = [ln for ln in difflib.unified_diff(golden, current, n=0) if ln.startswith("+") and not ln.startswith("+++")]
    return removed, added


def _evidence(removed: list[str], added: list[str], limit: int = 3) -> str:
    parts = [ln.strip() for ln in (removed[:limit] + added[:limit])]
    return " | ".join(parts)[:300]


def compare_to_baseline(
    device: str,
    config: str,
    profile: BaselineProfile,
    golden: str | None = None,
) -> list[Finding]:
    """Report how a device config drifted from the approved template."""
    golden_text = golden if golden is not None else profile.golden_config()
    style = profile.block_style()
    findings: list[Finding] = []

    if not profile.sections:
        golden_lines = _normalize(golden_text.splitlines(), profile.ignore)
        current_lines = _normalize(config.splitlines(), profile.ignore)
        removed, added = _diff_counts(golden_lines, current_lines)
        if removed or added:
            findings.append(
                Finding(
                    rule_id=DRIFT_RULE,
                    title=f"Config drifted from baseline '{profile.name}'",
                    severity=profile.severity,
                    device=device,
                    detail=f"{len(removed)} line(s) missing, {len(added)} unexpected",
                    evidence=_evidence(removed, added),
                    remediation=(
                        f"Compare against {profile.golden_path()} and either fix the device "
                        "or approve the change by updating the baseline."
                    ),
                )
            )
        return findings

    golden_sections = extract_sections(golden_text, profile.sections, style)
    device_sections = extract_sections(config, profile.sections, style)

    for pattern in profile.sections:
        golden_block = golden_sections.get(pattern)
        device_block = device_sections.get(pattern)
        label = _section_label(golden_block or device_block, pattern)

        if golden_block and not device_block:
            findings.append(
                Finding(
                    rule_id=MISSING_RULE,
                    title=f"Baseline section missing: {label}",
                    severity=profile.severity,
                    device=device,
                    detail=f"Baseline '{profile.name}' requires this section",
                    evidence=golden_block[0].strip()[:200],
                    remediation=f"Apply the approved block from {profile.golden_path()}",
                )
            )
            continue
        if device_block and not golden_block:
            findings.append(
                Finding(
                    rule_id=EXTRA_RULE,
                    title=f"Section not present in baseline: {label}",
                    severity=profile.severity,
                    device=device,
                    detail=f"Baseline '{profile.name}' does not define this section",
                    evidence=device_block[0].strip()[:200],
                    remediation="Remove the section or extend the baseline if it is intended",
                )
            )
            continue
        if not golden_block or not device_block:
            continue

        golden_lines = _normalize(golden_block, profile.ignore)
        current_lines = _normalize(device_block, profile.ignore)
        removed, added = _diff_counts(golden_lines, current_lines)
        if removed or added:
            findings.append(
                Finding(
                    rule_id=DRIFT_RULE,
                    title=f"Baseline drift in {label}",
                    severity=profile.severity,
                    device=device,
                    detail=f"{len(removed)} line(s) missing, {len(added)} unexpected",
                    evidence=_evidence(removed, added),
                    remediation=(
                        f"Reconcile with {profile.golden_path()}; update the baseline if the "
                        "change was approved."
                    ),
                )
            )

    return findings


def _section_label(block: list[str] | None, pattern: str) -> str:
    if block:
        return block[0].strip()[:80]
    # Fall back to a readable form of the regex
    return re.sub(r"[\\^$(?i)]", "", pattern).strip()[:80] or pattern
