"""A scriptable in-process SSH server that imitates network device CLIs.

Used to exercise the parts of `netaudit.ssh_backup` that cannot be covered with
mocks: prompt detection, pager handling, command echo stripping, authentication
failures, and host key pinning.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from dataclasses import dataclass, field

import paramiko

# Generating a key per test is slow; one per session is plenty.
_HOST_KEYS: dict[str, paramiko.RSAKey] = {}


def host_key(name: str = "default") -> paramiko.RSAKey:
    """Cached RSA host key, so a test can simulate a replaced device key."""
    if name not in _HOST_KEYS:
        _HOST_KEYS[name] = paramiko.RSAKey.generate(2048)
    return _HOST_KEYS[name]


@dataclass
class DeviceScript:
    """What the fake device answers."""

    prompt: str
    config: str
    username: str = "admin"
    password: str = "secret"
    # Emit "--More--" every N lines and wait for a keypress before continuing
    pager_every: int = 0
    echo_command: bool = True
    accepted_commands: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)


class _Server(paramiko.ServerInterface):
    def __init__(self, script: DeviceScript) -> None:
        self.script = script
        self.shell_requested = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.script.username and password == self.script.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested.set()
        return True

    def check_channel_pty_request(self, *args: object, **kwargs: object) -> bool:
        return True


class _BastionServer(paramiko.ServerInterface):
    """Accepts password auth and direct-tcpip forwarding, like a jump host."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.destinations: list[tuple[str, int]] = []

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_direct_tcpip_request(
        self, chanid: int, origin: tuple[str, int], destination: tuple[str, int]
    ) -> int:
        self.destinations.append(destination)
        return paramiko.OPEN_SUCCEEDED


class FakeBastion:
    """Minimal jump host that forwards direct-tcpip channels to the real target."""

    def __init__(
        self, username: str = "netops", password: str = "jump", key_name: str = "bastion"
    ) -> None:
        self.host_key = host_key(key_name)
        self.server = _BastionServer(username, password)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.host, self.port = self.listener.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.error: Exception | None = None

    def __enter__(self) -> FakeBastion:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        with contextlib.suppress(OSError):
            self.listener.close()

    @property
    def forwarded(self) -> list[tuple[str, int]]:
        return list(self.server.destinations)

    def _serve(self) -> None:
        transport = None
        try:
            self.listener.settimeout(15)
            client_sock, _addr = self.listener.accept()
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)
            transport.start_server(server=self.server)

            channel = transport.accept(10)
            if channel is None:
                return
            destination = self.server.destinations[-1]
            upstream = socket.create_connection(destination, timeout=10)
            self._pump(channel, upstream)
        except Exception as exc:  # noqa: BLE001 - surfaced through self.error
            self.error = exc
        finally:
            if transport is not None:
                # Keep the transport alive until the tunnel drains, then drop it
                with contextlib.suppress(Exception):
                    transport.close()

    @staticmethod
    def _pump(channel: paramiko.Channel, upstream: socket.socket) -> None:
        def forward(src, dst) -> None:
            try:
                while True:
                    data = src.recv(32768)
                    if not data:
                        break
                    dst.sendall(data)
            except (OSError, EOFError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.close()

        up = threading.Thread(target=forward, args=(channel, upstream), daemon=True)
        down = threading.Thread(target=forward, args=(upstream, channel), daemon=True)
        up.start()
        down.start()
        up.join(30)
        down.join(1)


class FakeDevice:
    """Context manager exposing host/port of a one-shot fake device."""

    def __init__(self, script: DeviceScript, key_name: str = "default", port: int = 0) -> None:
        self.script = script
        self.host_key = host_key(key_name)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", port))
        self.listener.listen(1)
        self.host, self.port = self.listener.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.error: Exception | None = None

    def __enter__(self) -> FakeDevice:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.listener.close()

    @property
    def fingerprint(self) -> str:
        from netaudit.ssh_backup import key_fingerprint

        return key_fingerprint(self.host_key)

    def _serve(self) -> None:
        transport = None
        try:
            self.listener.settimeout(15)
            client_sock, _addr = self.listener.accept()
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)
            server = _Server(self.script)
            transport.start_server(server=server)

            channel = transport.accept(10)
            if channel is None:
                return
            server.shell_requested.wait(10)
            self._shell(channel)
        except Exception as exc:  # noqa: BLE001 - surfaced through self.error
            self.error = exc
        finally:
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
            self.close()

    def _shell(self, channel: paramiko.Channel) -> None:
        script = self.script
        channel.send(f"\r\n{script.prompt}")
        buffer = ""
        deadline = threading.Event()

        while not deadline.is_set():
            try:
                data = channel.recv(4096)
            except (OSError, EOFError):
                return
            if not data:
                return
            buffer += data.decode("utf-8", errors="replace")

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                command = line.strip()
                script.received.append(command)
                if script.echo_command:
                    channel.send(f"{command}\r\n")
                if self._is_config_command(command):
                    self._send_config(channel)
                channel.send(script.prompt)

    def _is_config_command(self, command: str) -> bool:
        if self.script.accepted_commands:
            return any(command.startswith(c) for c in self.script.accepted_commands)
        return command.startswith("show running-config") or command.startswith(
            "show full-configuration"
        )

    def _send_config(self, channel: paramiko.Channel) -> None:
        lines = self.script.config.splitlines()
        for index, line in enumerate(lines, start=1):
            channel.send(line + "\r\n")
            if self.script.pager_every and index % self.script.pager_every == 0:
                channel.send("--More--")
                # Wait for the client to acknowledge the pager
                try:
                    channel.recv(16)
                except (OSError, EOFError):
                    return
                channel.send("\r      \r")
