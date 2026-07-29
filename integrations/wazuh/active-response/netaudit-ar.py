#!/usr/bin/env python3
"""
Wazuh Active Response: pull a fresh config when an alert says a device changed.

Install on the Wazuh manager (or on the agent that can reach the device):

    cp netaudit-ar.py /var/ossec/active-response/bin/netaudit-ar.py
    chmod 750 /var/ossec/active-response/bin/netaudit-ar.py
    chown root:wazuh /var/ossec/active-response/bin/netaudit-ar.py

Wazuh hands the alert to this script on stdin as JSON, expects an ack on stdout
for "check keys", and reads nothing else. Everything we want to see goes to
active-responses.log, and the interesting output is shipped back into Wazuh by
netaudit itself (NETAUDIT_WAZUH_FILE below).

Configuration comes from the environment so no secrets live in this file:

    NETAUDIT_BIN          path to the netaudit executable (default: netaudit)
    NETAUDIT_WORKDIR      directory holding inventory.yaml / .env (default: /opt/netaudit)
    NETAUDIT_WAZUH_FILE   NDJSON file the agent tails
                          (default: /var/ossec/logs/netaudit-events.json)
    NETAUDIT_TIMEOUT      seconds before the backup is abandoned (default: 180)
    NETAUDIT_DEVICE_MAP   optional JSON mapping agent name or IP to device name,
                          e.g. {"fw-edge":"fg-120g-01","192.168.20.10":"scalance-xc208-01"}
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(os.environ.get("NETAUDIT_AR_LOG", "/var/ossec/logs/active-responses.log"))
NETAUDIT_BIN = os.environ.get("NETAUDIT_BIN", "netaudit")
WORKDIR = os.environ.get("NETAUDIT_WORKDIR", "/opt/netaudit")
WAZUH_FILE = os.environ.get("NETAUDIT_WAZUH_FILE", "/var/ossec/logs/netaudit-events.json")
TIMEOUT = int(os.environ.get("NETAUDIT_TIMEOUT", "180"))

# netaudit respond exit codes
EXIT_MEANING = {
    0: "no change",
    1: "backup failed",
    2: "critical/high findings",
    3: "configuration changed",
}


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    line = f"{stamp} netaudit-ar: {message}\n"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def device_map() -> dict[str, str]:
    raw = os.environ.get("NETAUDIT_DEVICE_MAP", "").strip()
    if not raw:
        return {}
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError as exc:
        log(f"NETAUDIT_DEVICE_MAP is not valid JSON: {exc}")
        return {}
    return {str(k).lower(): str(v) for k, v in mapping.items()} if isinstance(mapping, dict) else {}


def _candidates(alert: dict) -> list[str]:
    """Every hint the alert gives us about which device it is about."""
    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    hints = [
        data.get("netaudit", {}).get("device") if isinstance(data.get("netaudit"), dict) else None,
        data.get("device"),
        data.get("devname"),  # FortiOS event logs carry the hostname here
        data.get("dstname"),
        agent.get("name"),
        agent.get("ip"),
        data.get("srcip"),
        (alert.get("manager") or {}).get("name"),
    ]
    return [str(h) for h in hints if h]


def resolve_device(alert: dict, mapping: dict[str, str]) -> str | None:
    for hint in _candidates(alert):
        mapped = mapping.get(hint.lower())
        if mapped:
            return mapped
    # Without a mapping entry, fall back to the first hint and let netaudit
    # reject it if the name is not in the inventory.
    hints = _candidates(alert)
    return hints[0] if hints else None


def trigger_label(alert: dict) -> str:
    rule = alert.get("rule") or {}
    rule_id = rule.get("id", "?")
    description = str(rule.get("description", "")).strip()
    return f"wazuh rule {rule_id}: {description}"[:200]


def run_netaudit(device: str, reason: str, agent: str) -> int:
    command = [
        NETAUDIT_BIN,
        "respond",
        "--device",
        device,
        "--reason",
        reason,
        "--wazuh-file",
        WAZUH_FILE,
    ]
    if agent:
        command += ["--agent", agent]

    log(f"running: {' '.join(command)} (cwd={WORKDIR})")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            cwd=WORKDIR,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        log(f"netaudit not found at '{NETAUDIT_BIN}' - set NETAUDIT_BIN")
        return 1
    except subprocess.TimeoutExpired:
        log(f"netaudit respond timed out after {TIMEOUT}s for {device}")
        return 1

    for stream_name, stream in (("stdout", completed.stdout), ("stderr", completed.stderr)):
        for line in (stream or "").splitlines():
            if line.strip():
                log(f"{stream_name}: {line.rstrip()}")
    log(
        f"{device}: exit {completed.returncode} "
        f"({EXIT_MEANING.get(completed.returncode, 'unknown')})"
    )
    return completed.returncode


def main() -> int:
    raw = sys.stdin.readline()
    if not raw.strip():
        log("no input on stdin")
        return 1

    try:
        message = json.loads(raw)
    except json.JSONDecodeError as exc:
        log(f"stdin is not valid JSON: {exc}")
        return 1

    command = message.get("command", "")
    if command == "check_keys":
        # Wazuh probes the script before using it
        print(json.dumps({"version": 1, "origin": {"name": "netaudit-ar", "module": "active-response"}, "command": "check_keys", "parameters": {"keys": []}}))
        sys.stdout.flush()
        return 0
    if command == "delete":
        log("ignoring 'delete' (this response has nothing to roll back)")
        return 0

    alert = ((message.get("parameters") or {}).get("alert")) or {}
    if not alert:
        log("alert payload missing from the AR message")
        return 1

    mapping = device_map()
    device = resolve_device(alert, mapping)
    if not device:
        log("could not work out which device the alert is about")
        return 1

    agent = str((alert.get("agent") or {}).get("name", ""))
    return run_netaudit(device, trigger_label(alert), agent)


if __name__ == "__main__":
    sys.exit(main())
