"""Manual check: receive netaudit syslog events on a local UDP socket.

Run from the repo root:
    python tests/manual/verify_syslog_receive.py

Starts a UDP listener on 127.0.0.1:5514, sends the findings of a sample
FortiGate config through the syslog transport, and prints what a Wazuh
manager would see on the wire.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

from netaudit.audit import audit_config, load_rules
from netaudit.wazuh_integration import send_wazuh_syslog

HOST, PORT = "127.0.0.1", 5514
SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "fg-120g-01.cfg"


def main() -> int:
    received: list[str] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    sock.settimeout(3.0)

    def listen() -> None:
        while True:
            try:
                data, _addr = sock.recvfrom(65535)
            except TimeoutError:
                return
            received.append(data.decode("utf-8"))

    listener = threading.Thread(target=listen, daemon=True)
    listener.start()

    text = SAMPLE.read_text(encoding="utf-8")
    rules = load_rules(platform="fortigate")
    findings = audit_config("fg-120g-01", text, rules, platform="fortigate")
    sent = send_wazuh_syslog(findings, HOST, port=PORT, protocol="udp")

    listener.join(timeout=5)
    sock.close()

    print(f"sent={sent} received={len(received)}")
    for line in received[:3]:
        print(line[:160])

    ok = sent == len(received) and all(line.startswith("<134>") for line in received)
    print("OK" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
