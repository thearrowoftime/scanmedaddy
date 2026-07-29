"""SSH config backup for network devices (Cisco, FortiGate, SCALANCE, …)."""

from __future__ import annotations

import base64
import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import paramiko

from netaudit.models import Device, JumpHost

# Pinned device keys live outside the repo tree by default (.netaudit is git-ignored)
DEFAULT_KNOWN_HOSTS = Path(".netaudit") / "known_hosts"

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
# After a keypress, devices erase the pager prompt with CR / backspaces / spaces.
# Those artifacts must be removed together with the prompt, otherwise the erase
# padding is glued to the next config line and corrupts the snapshot.
_PAGER_ARTIFACT = re.compile(
    r"[ \t\x08\r]*(?:--More--|---\(more\)---|Press any key[^\r\n]*|--More)[ \t\x08\r]*",
    re.IGNORECASE,
)
# Cisco: R1#, SCALANCE: cli# / cli>, FortiGate: FG120G #
_PROMPT_RE = re.compile(
    r"[\r\n](?:cli[#>]\s*|[\w.\-()/@]+[#>]\s*|[\w.\-]+(?:\([\w.\-]+\))?\s*[#$]\s*)$"
)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def _apply_line_edits(line: str) -> str:
    """Apply terminal editing: backspaces vanish, text after a bare CR wins."""
    line = line.replace("\x08", "")
    if "\r" in line:
        line = line.rsplit("\r", 1)[-1]
    return line


def _clean_output(raw: str, command: str) -> str:
    """Remove command echo, prompts, and pager artifacts."""
    text = _strip_ansi(raw)
    text = text.replace("\r\n", "\n")
    text = _PAGER_ARTIFACT.sub("", text)
    lines = [_apply_line_edits(line) for line in text.split("\n")]
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


class HostKeyMismatch(SSHBackupError):
    """The device presented a different host key than the pinned one."""


class HostKeyUnknown(SSHBackupError):
    """The device key is not pinned yet and strict mode forbids learning it."""


@dataclass
class HostKeyEvent:
    """Reported whenever a host key is learned or fails verification."""

    device: str
    target: str
    fingerprint: str
    status: str  # learned | mismatch | unknown
    expected: str = ""


HostKeySink = Callable[[HostKeyEvent], None]


def key_fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH-style SHA256 fingerprint, e.g. SHA256:Ab3d..."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def host_key_name(host: str, port: int) -> str:
    """known_hosts entry name, matching OpenSSH/paramiko conventions."""
    return host if port == 22 else f"[{host}]:{port}"


def is_host_pinned(host: str, port: int, known_hosts: str | Path | None) -> bool:
    """True when a key for this host is already recorded in known_hosts."""
    if not known_hosts:
        return False
    path = Path(known_hosts)
    if not path.exists():
        return False
    keys = paramiko.HostKeys()
    try:
        keys.load(str(path))
    except OSError:
        return False
    return keys.lookup(host_key_name(host, port)) is not None


class _PinningPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-on-first-use, unless strict mode requires a pre-pinned key."""

    def __init__(
        self,
        known_hosts: Path | None,
        strict: bool,
        device_name: str,
        on_event: HostKeySink | None = None,
    ) -> None:
        self.known_hosts = known_hosts
        self.strict = strict
        self.device_name = device_name
        self.on_event = on_event

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        fingerprint = key_fingerprint(key)
        if self.strict:
            self._emit(hostname, fingerprint, "unknown")
            raise HostKeyUnknown(
                f"host key for {hostname} is not pinned ({fingerprint}); "
                "run once without --strict-host-keys to pin it"
            )
        client.get_host_keys().add(hostname, key.get_name(), key)
        if self.known_hosts:
            self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
            client.save_host_keys(str(self.known_hosts))
        self._emit(hostname, fingerprint, "learned")

    def _emit(self, hostname: str, fingerprint: str, status: str) -> None:
        if self.on_event:
            self.on_event(
                HostKeyEvent(
                    device=self.device_name,
                    target=hostname,
                    fingerprint=fingerprint,
                    status=status,
                )
            )


def _build_client(
    device_name: str,
    known_hosts: str | Path | None,
    strict_host_keys: bool,
    on_host_key: HostKeySink | None,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    path: Path | None = Path(known_hosts) if known_hosts else None
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        client.load_host_keys(str(path))
    client.set_missing_host_key_policy(
        _PinningPolicy(path, strict_host_keys, device_name, on_host_key)
    )
    return client


def _connect(
    client: paramiko.SSHClient,
    *,
    device_name: str,
    host: str,
    port: int,
    username: str,
    password: str,
    key_file: str,
    key_passphrase: str,
    timeout: int,
    sock: paramiko.Channel | None = None,
    on_host_key: HostKeySink | None = None,
) -> None:
    """Connect, translating host key problems into explicit errors."""
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password or None,
            key_filename=key_file or None,
            passphrase=key_passphrase or None,
            timeout=min(timeout, 30),
            look_for_keys=not key_file,
            allow_agent=not key_file,
            banner_timeout=30,
            sock=sock,
        )
    except paramiko.BadHostKeyException as exc:
        got = key_fingerprint(exc.key)
        expected = key_fingerprint(exc.expected_key)
        if on_host_key:
            on_host_key(
                HostKeyEvent(
                    device=device_name,
                    target=host_key_name(host, port),
                    fingerprint=got,
                    status="mismatch",
                    expected=expected,
                )
            )
        raise HostKeyMismatch(
            f"host key mismatch for {host}:{port} - pinned {expected}, got {got}. "
            "Investigate before removing the pin (device replaced, or interception)"
        ) from exc


def _open_jump_channel(
    device: Device,
    jump: JumpHost,
    *,
    known_hosts: str | Path | None,
    strict_host_keys: bool,
    timeout: int,
    on_host_key: HostKeySink | None,
    log: Callable[[str], None],
) -> tuple[paramiko.SSHClient, paramiko.Channel]:
    """Open a direct-tcpip channel to the device through a bastion."""
    log(f"Jump host: connecting to {jump.label}")
    jump_client = _build_client(
        f"{device.name} (jump)", known_hosts, strict_host_keys, on_host_key
    )
    try:
        _connect(
            jump_client,
            device_name=f"{device.name} (jump)",
            host=jump.host,
            port=jump.port,
            username=jump.username or device.username,
            password=jump.password,
            key_file=jump.key_file,
            key_passphrase=jump.key_passphrase,
            timeout=timeout,
            on_host_key=on_host_key,
        )
        transport = jump_client.get_transport()
        if transport is None:
            raise SSHBackupError(f"jump host {jump.label} did not provide a transport")
        channel = transport.open_channel(
            "direct-tcpip", (device.host, device.port), ("127.0.0.1", 0)
        )
        log(f"Jump host: tunnel open to {device.host}:{device.port}")
        return jump_client, channel
    except Exception:
        jump_client.close()
        raise


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
    progress: Callable[[str], None] | None = None,
    known_hosts: str | Path | None = DEFAULT_KNOWN_HOSTS,
    strict_host_keys: bool = False,
    on_host_key: HostKeySink | None = None,
) -> str:
    """
    Connect over SSH and pull running configuration.

    Supports cisco_ios, cisco_asa, fortigate/fortios (FortiGate 120G),
    scalance/scalance_xc (SCALANCE XC208), juniper, generic.

    Device keys are verified against `known_hosts`. Unknown keys are pinned on
    first use and reported through `on_host_key`; with `strict_host_keys` an
    unpinned key aborts the run instead. A changed key always aborts.
    """
    log = progress or (lambda _m: None)
    platform = device.platform.lower()
    command = SHOW_COMMANDS.get(platform, SHOW_COMMANDS["generic"])
    timeout = timeout or PLATFORM_TIMEOUTS.get(platform, 45)

    client = _build_client(device.name, known_hosts, strict_host_keys, on_host_key)
    jump_client: paramiko.SSHClient | None = None

    try:
        sock: paramiko.Channel | None = None
        if device.jump is not None:
            jump_client, sock = _open_jump_channel(
                device,
                device.jump,
                known_hosts=known_hosts,
                strict_host_keys=strict_host_keys,
                timeout=timeout,
                on_host_key=on_host_key,
                log=log,
            )

        auth = "key" if device.key_file else "password"
        log(f"Connecting to {device.name} ({device.host}:{device.port}) [{platform}, {auth}]...")
        _connect(
            client,
            device_name=device.name,
            host=device.host,
            port=device.port,
            username=device.username,
            password=device.password,
            key_file=device.key_file,
            key_passphrase=device.key_passphrase,
            timeout=timeout,
            sock=sock,
            on_host_key=on_host_key,
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
        if jump_client is not None:
            jump_client.close()


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
    acked_upto = 0  # pager prompts before this offset were already answered
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
            # One keypress per pager prompt: acknowledging twice skips a screen
            search_from = max(acked_upto, len(buf) - 120)
            if _PAGER_PROMPTS.search(buf, search_from):
                channel.send(" ")
                acked_upto = len(buf)
        else:
            idle_rounds += 1
            time.sleep(0.15)
            if idle_rounds > 12 and len(buf) > 100 and _PROMPT_RE.search(buf.replace("\r", "")):
                return buf
    if not buf.strip():
        raise SSHBackupError("Timed out waiting for config output")
    return buf
