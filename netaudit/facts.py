"""Inventory facts extracted from stored configs.

Answers the questions an auditor asks first: what is this box, what firmware is
it running, which VLANs and interfaces exist, who can administer it. Everything
comes from the config snapshots that are already collected, so no extra device
access is needed.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from netaudit.models import Finding, Severity

FIRMWARE_RULES_FILE = "firmware.yaml"

# #config-version=FG120G-7.2.5-FW-build1517-230606:opmode=0:vdom=0
_FG_CONFIG_VERSION = re.compile(
    r"^#config-version=([A-Za-z0-9]+)-(\d+(?:\.\d+)+)-FW-build(\d+)", re.MULTILINE
)
_FG_HOSTNAME = re.compile(r'^\s*set\s+hostname\s+"?([^"\s]+)"?', re.MULTILINE | re.IGNORECASE)
_FG_SERIAL = re.compile(r"^#?\s*serial-number[=:\s]+([A-Za-z0-9]+)", re.MULTILINE | re.IGNORECASE)

_IOS_HOSTNAME = re.compile(r"^\s*hostname\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_IOS_VERSION = re.compile(r"^\s*version\s+(\d+(?:\.\d+)*)", re.MULTILINE | re.IGNORECASE)
_IOS_USERNAME = re.compile(r"^\s*username\s+(\S+)", re.MULTILINE | re.IGNORECASE)

# SCALANCE snapshots carry firmware in a header comment, e.g.
# "! SCALANCE XC208 firmware V04.05.00" or "! Firmware version: V4.5"
_SCALANCE_FIRMWARE = re.compile(
    r"^[!#].*?firmware(?:\s+version)?[:\s]+V?(\d+(?:\.\d+)+)",
    re.MULTILINE | re.IGNORECASE,
)
_SCALANCE_MODEL = re.compile(r"(SCALANCE\s+X[\w\-]*)", re.IGNORECASE)


@dataclass
class DeviceFacts:
    device: str
    platform: str
    hostname: str = ""
    model: str = ""
    firmware: str = ""
    build: str = ""
    serial: str = ""
    vlans: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    admins: list[str] = field(default_factory=list)
    mgmt_addresses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def firmware_label(self) -> str:
        if self.firmware and self.build:
            return f"{self.firmware} (build {self.build})"
        return self.firmware or "unknown"


def _unique(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value and value not in seen:
            seen[value] = None
    return list(seen)


def _fortigate_facts(facts: DeviceFacts, config: str) -> None:
    version = _FG_CONFIG_VERSION.search(config)
    if version:
        facts.model, facts.firmware, facts.build = (
            version.group(1),
            version.group(2),
            version.group(3),
        )
    hostname = _FG_HOSTNAME.search(config)
    if hostname:
        facts.hostname = hostname.group(1)
    serial = _FG_SERIAL.search(config)
    if serial:
        facts.serial = serial.group(1)

    section: str | None = None
    for raw in config.splitlines():
        line = raw.strip()
        if line.startswith("config "):
            section = line[len("config ") :].strip().lower()
            continue
        if line == "end":
            section = None
            continue
        if section is None:
            continue

        edit = re.match(r'(?i)^edit\s+"?([^"\n]+?)"?$', line)
        if edit and section == "system interface":
            facts.interfaces.append(edit.group(1))
        elif edit and section == "system admin":
            facts.admins.append(edit.group(1))

        vlan = re.match(r"(?i)^set\s+vlanid\s+(\d+)", line)
        if vlan:
            facts.vlans.append(vlan.group(1))
        address = re.match(r"(?i)^set\s+ip\s+(\d+\.\d+\.\d+\.\d+)", line)
        if address and section == "system interface":
            facts.mgmt_addresses.append(address.group(1))


def _ios_style_facts(facts: DeviceFacts, config: str) -> None:
    hostname = _IOS_HOSTNAME.search(config)
    if hostname:
        facts.hostname = hostname.group(1)
    facts.admins = _unique(_IOS_USERNAME.findall(config))

    firmware = _SCALANCE_FIRMWARE.search(config)
    if firmware:
        facts.firmware = firmware.group(1)
    else:
        version = _IOS_VERSION.search(config)
        if version:
            facts.firmware = version.group(1)

    model = _SCALANCE_MODEL.search(config)
    if model:
        facts.model = re.sub(r"\s+", " ", model.group(1)).upper()

    for raw in config.splitlines():
        line = raw.strip()
        vlan = re.match(r"(?i)^(?:interface\s+vlan|vlan)\s+(\d[\d,\-]*)$", line)
        if vlan:
            facts.vlans.append(vlan.group(1))
        interface = re.match(r"(?i)^interface\s+(.+?)\s*$", line)
        if interface:
            facts.interfaces.append(re.sub(r"\s+", " ", interface.group(1)))
        address = re.match(r"(?i)^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)", line)
        if address:
            facts.mgmt_addresses.append(address.group(1))


def extract_facts(device: str, config: str, platform: str | None = None) -> DeviceFacts:
    """Pull inventory facts out of a config snapshot."""
    platform = (platform or "").lower()
    facts = DeviceFacts(device=device, platform=platform or "unknown")

    if platform in ("fortigate", "fortios"):
        _fortigate_facts(facts, config)
    else:
        _ios_style_facts(facts, config)

    facts.vlans = _unique(facts.vlans)
    facts.interfaces = _unique(facts.interfaces)
    facts.admins = _unique(facts.admins)
    facts.mgmt_addresses = _unique(facts.mgmt_addresses)
    if not facts.hostname:
        facts.hostname = device
    return facts


def version_tuple(version: str) -> tuple[int, ...]:
    """Comparable version: 'V04.05.00' and '4.5' both normalise sensibly."""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else ()


def load_firmware_policy(path: str | Path | None = None) -> dict[str, Any]:
    """Minimum accepted firmware per platform (see netaudit/rules/firmware.yaml)."""
    if path:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    try:
        text = (resources.files("netaudit.rules") / FIRMWARE_RULES_FILE).read_text(encoding="utf-8")
    except (FileNotFoundError, TypeError, AttributeError):
        text = (Path(__file__).parent / "rules" / FIRMWARE_RULES_FILE).read_text(encoding="utf-8")
    return yaml.safe_load(text) or {}


def firmware_findings(
    facts: DeviceFacts,
    policy: dict[str, Any] | None = None,
) -> list[Finding]:
    """Compare detected firmware against the configured minimum."""
    policy = policy if policy is not None else load_firmware_policy()
    minimums = {k.lower(): str(v) for k, v in (policy.get("minimum") or {}).items()}
    settings = policy.get("policy") or {}
    reference = str(settings.get("reference", "")).strip()
    minimum = minimums.get(facts.platform)

    if not minimum:
        return []

    if not facts.firmware:
        return [
            Finding(
                rule_id=str(settings.get("unknown_rule_id", "FW-UNKNOWN")),
                title="Firmware version could not be determined",
                severity=Severity(str(settings.get("unknown_severity", "low"))),
                device=facts.device,
                detail=(
                    f"No firmware version in the {facts.platform} snapshot; "
                    f"minimum required is {minimum}"
                ),
                remediation=(
                    "Capture the version banner in the backup (FortiGate stores it in the "
                    "#config-version header; for SCALANCE add 'show version' output) so "
                    "patch level can be audited."
                ),
            )
        ]

    if version_tuple(facts.firmware) >= version_tuple(minimum):
        return []

    detail = f"Runs {facts.firmware_label}, minimum accepted is {minimum}"
    return [
        Finding(
            rule_id=str(settings.get("rule_id", "FW-OUTDATED")),
            title="Firmware older than the accepted minimum",
            severity=Severity(str(settings.get("severity", "high"))),
            device=facts.device,
            detail=detail,
            evidence=facts.firmware_label,
            remediation=(
                f"Plan an upgrade to {minimum} or later"
                + (f". Check {reference}" if reference else "")
            ),
        )
    ]


def facts_findings(
    device: str,
    config: str,
    platform: str | None = None,
    policy: dict[str, Any] | None = None,
) -> tuple[DeviceFacts, list[Finding]]:
    """Convenience wrapper: extract facts and evaluate the firmware policy."""
    facts = extract_facts(device, config, platform)
    return facts, firmware_findings(facts, policy)
