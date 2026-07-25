"""Device inventory loader (YAML)."""

from __future__ import annotations

from pathlib import Path

import yaml

from netaudit.models import Device


def load_inventory(path: str | Path) -> list[Device]:
    """Load devices from a YAML inventory file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Inventory not found: {p}")

    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    devices_raw = raw.get("devices", raw if isinstance(raw, list) else [])
    if not isinstance(devices_raw, list):
        raise ValueError("Inventory must contain a 'devices' list")

    devices: list[Device] = []
    for entry in devices_raw:
        if not isinstance(entry, dict):
            continue
        devices.append(Device.from_dict(entry))
    return devices


INVENTORY_TEMPLATE = """\
# Passwords are references, never literals. Supported schemes:
#   env:NAME                 environment variable (also from .env)
#   file:C:\\secrets\\fg.txt   first line of a file
#   wincred:netaudit/fg-01   Windows Credential Manager generic credential
#   keyring:netaudit/fg-01   keyring package (service/username)
#   prompt                   ask interactively (not for scheduled runs)
# Leaving the field empty falls back to NETAUDIT_<DEVICE>_PASSWORD.
# Verify with: netaudit secrets

devices:
  - name: fg-120g-01
    host: 192.168.10.1
    device_type: firewall
    platform: fortigate
    username: admin
    password: env:FG_120G_01_PASSWORD
    port: 22
    tags: [edge, fortigate, lab]

  - name: scalance-xc208-01
    host: 192.168.20.10
    device_type: switch
    platform: scalance_xc
    username: admin
    password: env:SCALANCE_XC208_01_PASSWORD
    port: 22
    tags: [ot, siemens, lab]

  - name: core-sw-01
    host: 192.168.1.10
    device_type: switch
    platform: cisco_ios
    username: admin
    password: wincred:netaudit/core-sw-01
    enable_password: env:CORE_SW_01_ENABLE_PASSWORD
    port: 22
    tags: [core, lab]
"""


def save_inventory_template(path: str | Path) -> Path:
    """Write an example inventory file with FortiGate 120G + SCALANCE XC208."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(INVENTORY_TEMPLATE, encoding="utf-8")
    return p


def platform_for_device(inventory_path: str | Path, device_name: str) -> str | None:
    """Lookup platform from inventory by device name."""
    try:
        for d in load_inventory(inventory_path):
            if d.name == device_name:
                return d.platform
    except FileNotFoundError:
        return None
    return None
