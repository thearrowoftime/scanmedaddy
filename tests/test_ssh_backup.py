"""SSH backup tests against an in-process fake device (see fake_ssh.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fake_ssh import DeviceScript, FakeBastion, FakeDevice, host_key

from netaudit.models import Device, JumpHost
from netaudit.ssh_backup import (
    HostKeyEvent,
    HostKeyMismatch,
    HostKeyUnknown,
    SSHBackupError,
    backup_device,
    host_key_name,
    is_host_pinned,
)

FORTIGATE_CONFIG = """\
#config-version=FG120G-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "fg-120g-01"
end
config firewall policy
    edit 1
        set name "allow-all"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""

SCALANCE_CONFIG = """\
hostname scalance-xc208-01
snmp-server community public RO
telnet server enable
end
"""


def _device(port: int, platform: str = "fortigate", **kwargs) -> Device:
    base = {
        "name": "fake-device",
        "host": "127.0.0.1",
        "port": port,
        "platform": platform,
        "username": "admin",
        "password": "secret",
    }
    base.update(kwargs)
    return Device(**base)


def _known_hosts(tmp_path: Path) -> str:
    return str(tmp_path / "known_hosts")


def test_fortigate_prompt_and_command_echo(tmp_path: Path):
    script = DeviceScript(prompt="FG120G-01 # ", config=FORTIGATE_CONFIG)
    with FakeDevice(script) as device:
        config = backup_device(
            _device(device.port),
            timeout=15,
            known_hosts=_known_hosts(tmp_path),
        )

    assert "config firewall policy" in config
    # command echo and trailing prompt must not leak into the snapshot
    assert "show full-configuration" not in config
    assert "FG120G-01 #" not in config
    assert config.endswith("\n")
    assert script.received[-1].startswith("show full-configuration")


def test_scalance_prompt(tmp_path: Path):
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)
    with FakeDevice(script) as device:
        config = backup_device(
            _device(device.port, platform="scalance_xc"),
            timeout=15,
            known_hosts=_known_hosts(tmp_path),
        )

    assert "telnet server enable" in config
    assert "cli#" not in config
    # paging is disabled before pulling the config
    assert any(cmd.startswith(("terminal length", "no paging", "set cli")) for cmd in script.received)


def test_pager_is_answered_and_stripped(tmp_path: Path):
    long_config = "\n".join(f"set line-{i} value" for i in range(1, 41))
    script = DeviceScript(prompt="cli# ", config=long_config, pager_every=10)
    with FakeDevice(script) as device:
        config = backup_device(
            _device(device.port, platform="scalance_xc"),
            timeout=20,
            known_hosts=_known_hosts(tmp_path),
        )

    assert "--More--" not in config
    assert "set line-1 value" in config
    assert "set line-40 value" in config
    assert len([ln for ln in config.splitlines() if ln.startswith("set line-")]) == 40


def test_cisco_enable_sequence(tmp_path: Path):
    script = DeviceScript(prompt="core-sw-01#", config="hostname core-sw-01\nend\n")
    with FakeDevice(script) as device:
        backup_device(
            _device(device.port, platform="cisco_ios", enable_password="enablepw"),
            timeout=15,
            known_hosts=_known_hosts(tmp_path),
        )

    assert "terminal length 0" in script.received
    assert "enable" in script.received


def test_bad_password_raises(tmp_path: Path):
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG, password="right")
    with FakeDevice(script) as device:
        with pytest.raises(SSHBackupError, match="SSH backup failed"):
            backup_device(
                _device(device.port, platform="scalance_xc", password="wrong"),
                timeout=15,
                known_hosts=_known_hosts(tmp_path),
            )


def test_empty_config_is_rejected(tmp_path: Path):
    script = DeviceScript(prompt="cli# ", config="short\n")
    with FakeDevice(script) as device:
        with pytest.raises(SSHBackupError, match="looks empty"):
            backup_device(
                _device(device.port, platform="scalance_xc"),
                timeout=15,
                known_hosts=_known_hosts(tmp_path),
            )


def test_host_key_is_pinned_on_first_use(tmp_path: Path):
    known_hosts = _known_hosts(tmp_path)
    events: list[HostKeyEvent] = []
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)

    with FakeDevice(script) as device:
        port = device.port
        backup_device(
            _device(port, platform="scalance_xc"),
            timeout=15,
            known_hosts=known_hosts,
            on_host_key=events.append,
        )
        expected_fingerprint = device.fingerprint

    assert [e.status for e in events] == ["learned"]
    assert events[0].fingerprint == expected_fingerprint
    assert events[0].target == host_key_name("127.0.0.1", port)
    assert is_host_pinned("127.0.0.1", port, known_hosts)


def test_strict_mode_refuses_unpinned_key(tmp_path: Path):
    events: list[HostKeyEvent] = []
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)

    with FakeDevice(script) as device:
        with pytest.raises(HostKeyUnknown, match="not pinned"):
            backup_device(
                _device(device.port, platform="scalance_xc"),
                timeout=15,
                known_hosts=_known_hosts(tmp_path),
                strict_host_keys=True,
                on_host_key=events.append,
            )

    assert [e.status for e in events] == ["unknown"]
    assert not is_host_pinned("127.0.0.1", device.port, _known_hosts(tmp_path))


def test_changed_host_key_aborts_with_both_fingerprints(tmp_path: Path):
    """A device that swaps its key mid-life must not be backed up silently."""
    known_hosts = _known_hosts(tmp_path)
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)
    events: list[HostKeyEvent] = []

    # First run pins the original key; reuse the port so known_hosts matches.
    with FakeDevice(script, key_name="original") as device:
        port = device.port
        backup_device(
            _device(port, platform="scalance_xc"),
            timeout=15,
            known_hosts=known_hosts,
        )
        original_fingerprint = device.fingerprint

    impostor = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)
    with FakeDevice(impostor, key_name="rotated", port=port) as device:
        with pytest.raises(HostKeyMismatch) as excinfo:
            backup_device(
                _device(port, platform="scalance_xc"),
                timeout=15,
                known_hosts=known_hosts,
                on_host_key=events.append,
            )
        rotated_fingerprint = device.fingerprint

    message = str(excinfo.value)
    assert original_fingerprint in message
    assert rotated_fingerprint in message
    assert [e.status for e in events] == ["mismatch"]
    assert events[0].expected == original_fingerprint
    assert events[0].fingerprint == rotated_fingerprint


def test_rotated_key_differs_from_original():
    assert host_key("original").asbytes() != host_key("rotated").asbytes()


def test_backup_through_jump_host(tmp_path: Path):
    """OT devices are usually only reachable through a bastion."""
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)
    with FakeDevice(script) as device, FakeBastion() as bastion:
        target = _device(
            device.port,
            platform="scalance_xc",
            jump=JumpHost(
                host=bastion.host,
                port=bastion.port,
                username="netops",
                password="jump",
            ),
        )
        config = backup_device(
            target,
            timeout=20,
            known_hosts=_known_hosts(tmp_path),
        )

    assert "telnet server enable" in config
    assert bastion.forwarded == [("127.0.0.1", device.port)]
    assert bastion.error is None


def test_jump_host_key_is_pinned_separately(tmp_path: Path):
    known_hosts = _known_hosts(tmp_path)
    events: list[HostKeyEvent] = []
    script = DeviceScript(prompt="cli# ", config=SCALANCE_CONFIG)

    with FakeDevice(script) as device, FakeBastion() as bastion:
        backup_device(
            _device(
                device.port,
                platform="scalance_xc",
                jump=JumpHost(host=bastion.host, port=bastion.port, username="netops", password="jump"),
            ),
            timeout=20,
            known_hosts=known_hosts,
            on_host_key=events.append,
        )

        assert is_host_pinned("127.0.0.1", bastion.port, known_hosts)
        assert is_host_pinned("127.0.0.1", device.port, known_hosts)

    # bastion first, then the device behind it
    assert [e.status for e in events] == ["learned", "learned"]
    assert events[0].device.endswith("(jump)")
