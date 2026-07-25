"""SSH config backup for network devices (Cisco, FortiGate, SCALANCE, …)."""

from __future__ import annotations

import re
import time
from typing import Callable

import paramiko

from netaudit.models import Device

# Commands that dump running config per platform
SHOW_COMMANDS: dict[str, str] = {
    "cisco_ios": "show running-config",
    "cisco_asa": "show running-config",
    "juniper": "show configuration | display set",
    # FortiGate 120G / FortiOS — grep . avoids --More-- without changing console settings
    "fortigate": "show full-configuration | grep .",
    "fortios": "show full-configuration | grep .",
    # SCALANCE XC208 (XC-200 series CLI)
    "scalance": "show running-config",
    "scalance_xc": "show running-config",
    "generic": "show running-config",
}

# Default read timeouts (FortiGate full-config can be large)
PLATFORM_TIMEOUTS: dict[str, int] = {
    "fortigate": 120,
    "fortios": 120,
    "scalance": 60,
    "scalance_xc": 60,
}

_PAGER_PROMPTS = re.compile(r"--More--|---\(more\)---|Press any key|--More", re.IGNORECASE)
# Cisco: R1#, SCALANCE: cli# / cli>, FortiGate: FG120G #
_PROMPT_RE = re.compile(
    r"[\r\n](?:cli[#>]\s*|[\w.\-()/@]+[#>]\s*|[\w.\-]+(?:\([\w.\-]+\))?\s*[#$]\s*)$"
)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def _clean_output(raw: str, command: str) -> str:
    """Remove command echo, prompts, and pager artifacts."""
    text = _strip_ansi(raw)
    text = text.replace("\r", "")
    text = _PAGER_PROMPTS.sub("", text)
    lines = text.splitlines()
    # Drop echo of command (may span first lines with pipe)
    cmd_head = command.split("|")[0].strip()
    if lines and (command.strip() in lines[0] or cmd_head in lines[0]):
        lines = lines[1:]
    while lines and _PROMPT_RE.search("\n" + lines[-1]):
        lines = lines[:-1]
    while lines and re.match(
        r"^(?:cli[#>]\s*|[\w.\-()/@]+[#>]\s*|[\w.\-]+(?:\([\w.\-]+\))?\s*[#$]\s*)$",
        lines[-1],
    ):
        lines = lines[:-1]
    return "\n".join(lines).strip() + "\n"


class SSHBackupError(Exception):
    """Raised when SSH backup fails."""


def check_reachable(device: Device, timeout: float = 5.0) -> tuple[bool, str]:
    """TCP-connect probe used by dry runs. Returns (reachable, detail)."""
    import socket

    try:
        with socket.create_connection((device.host, device.port), timeout=timeout):
            return True, f"tcp/{device.port} open"
    except OSError as exc:
        return False, f"tcp/{device.port} unreachable: {exc}"


def _prepare_session(channel: paramiko.Channel, device: Device, log: Callable[[str], None]) -> None:
    """Platform-specific session prep (paging, privilege)."""
    platform = device.platform.lower()

    if platform.startswith("cisco"):
        _send(channel, "terminal length 0")
        time.sleep(0.3)
        _drain(channel)
        if device.enable_password:
            _send(channel, "enable")
            time.sleep(0.3)
            buf = _drain(channel)
            if "assword" in buf.lower():
                _send(channel, device.enable_password)
                time.sleep(0.3)
                _drain(channel)

    elif platform in ("fortigate", "fortios"):
        # Prefer non-persistent paging bypass via | grep . in SHOW_COMMANDS.
        # Also try session-local console output if available (ignored if denied).
        log("FortiGate: preparing CLI (paging bypass via show | grep .)")
        _send(channel, "config system console")
        time.sleep(0.2)
        _drain(channel)
        _send(channel, "set output standard")
        time.sleep(0.2)
        _drain(channel)
        _send(channel, "end")
        time.sleep(0.3)
        _drain(channel)

    elif platform in ("scalance", "scalance_xc"):
        log("SCALANCE: disabling pager if supported")
        for cmd in ("terminal length 0", "no paging", "set cli pagination off"):
            _send(channel, cmd)
            time.sleep(0.25)
            _drain(channel)


def backup_device(
    device: Device,
    timeout: int | None = None,
    look_for_keys: bool = True,
    progress: Callable[[str], None] | None = None,
) -> str:
    """
    Connect over SSH and pull running configuration.

    Supports cisco_ios, cisco_asa, fortigate/fortios (FortiGate 120G),
    scalance/scalance_xc (SCALANCE XC208), juniper, generic.
    """
    log = progress or (lambda _m: None)
    platform = device.platform.lower()
    command = SHOW_COMMANDS.get(platform, SHOW_COMMANDS["generic"])
    timeout = timeout or PLATFORM_TIMEOUTS.get(platform, 45)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log(f"Connecting to {device.name} ({device.host}:{device.port}) [{platform}]...")
        client.connect(
            hostname=device.host,
            port=device.port,
            username=device.username,
            password=device.password or None,
            timeout=min(timeout, 30),
            look_for_keys=look_for_keys,
            allow_agent=look_for_keys,
            banner_timeout=30,
        )

        channel = client.invoke_shell(width=200, height=1000)
        channel.settimeout(timeout)
        time.sleep(0.8)
        _drain(channel)

        _prepare_session(channel, device, log)

        log(f"Pulling config: {command}")
        _send(channel, command)
        raw = _read_until_prompt(channel, timeout=timeout)
        config = _clean_output(raw, command)

        if len(config.strip()) < 20:
            raise SSHBackupError(
                f"Config from {device.name} looks empty — check credentials/platform"
            )

        log(f"Got {len(config)} bytes from {device.name}")
        return config
    except SSHBackupError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SSHBackupError(f"SSH backup failed for {device.name}: {exc}") from exc
    finally:
        client.close()


def _send(channel: paramiko.Channel, cmd: str) -> None:
    channel.send(cmd + "\n")


def _drain(channel: paramiko.Channel, wait: float = 0.2) -> str:
    time.sleep(wait)
    out = ""
    while channel.recv_ready():
        out += channel.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.05)
    return out


def _read_until_prompt(channel: paramiko.Channel, timeout: int = 45) -> str:
    """Read until we see a device prompt or timeout."""
    buf = ""
    deadline = time.time() + timeout
    idle_rounds = 0
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="replace")
            buf += chunk
            idle_rounds = 0
            cleaned = buf.replace("\r", "")
            if _PROMPT_RE.search(cleaned) and not _PAGER_PROMPTS.search(buf[-120:]):
                time.sleep(0.25)
                if channel.recv_ready():
                    continue
                return buf
            if _PAGER_PROMPTS.search(buf[-120:]):
                channel.send(" ")
        else:
            idle_rounds += 1
            time.sleep(0.15)
            if idle_rounds > 12 and len(buf) > 100 and _PROMPT_RE.search(buf.replace("\r", "")):
                return buf
    if not buf.strip():
        raise SSHBackupError("Timed out waiting for config output")
    return buf
