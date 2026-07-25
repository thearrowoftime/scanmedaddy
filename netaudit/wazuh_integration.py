"""Wazuh SIEM integration - JSON events for agent logcollector and syslog."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

from netaudit.models import Finding, Severity

# Map netaudit severity -> Wazuh rule level (approx)
SEVERITY_TO_LEVEL: dict[str, int] = {
    Severity.CRITICAL.value: 12,
    Severity.HIGH.value: 10,
    Severity.MEDIUM.value: 7,
    Severity.LOW.value: 5,
    Severity.INFO.value: 3,
}

# local0.info - matches the facility documented in integrations/wazuh/README.md
SYSLOG_PRI = 134
SYSLOG_TAG = "netaudit"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _envelope(payload: dict[str, Any], source: str = "netaudit") -> dict[str, Any]:
    return {"timestamp": _now_iso(), "integration": source, "netaudit": payload}


def finding_to_wazuh_event(finding: Finding, source: str = "netaudit") -> dict[str, Any]:
    """One NDJSON event consumable by Wazuh JSON decoder / localfile."""
    return _envelope(
        {
            "event_type": "finding",
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "device": finding.device,
            "detail": finding.detail,
            "line": finding.line,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "wazuh_level": SEVERITY_TO_LEVEL.get(finding.severity.value, 5),
        },
        source=source,
    )


def operational_event(
    event_type: str,
    *,
    device: str = "",
    severity: str = Severity.INFO.value,
    detail: str = "",
    source: str = "netaudit",
    **extra: Any,
) -> dict[str, Any]:
    """Build a non-finding event (backup_failed, backup_ok, run_summary, ...)."""
    payload: dict[str, Any] = {
        "event_type": event_type,
        "rule_id": f"NETAUDIT-{event_type.upper().replace('_', '-')}",
        "title": detail or event_type.replace("_", " ").title(),
        "severity": severity,
        "device": device,
        "detail": detail,
        "wazuh_level": SEVERITY_TO_LEVEL.get(severity, 5),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    return _envelope(payload, source=source)


def export_wazuh_events_ndjson(
    events: list[dict[str, Any]],
    path: str | Path,
    append: bool = True,
) -> Path:
    """Write raw events as NDJSON (one JSON object per line)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append and p.exists() else "w"
    with p.open(mode, encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return p


def export_wazuh_ndjson(findings: list[Finding], path: str | Path, append: bool = True) -> Path:
    """
    Write findings as NDJSON.

    Point a Wazuh agent <localfile> with log_format=json at this file.
    """
    return export_wazuh_events_ndjson(
        [finding_to_wazuh_event(f) for f in findings], path, append=append
    )


def format_syslog_line(event: dict[str, Any], hostname: str | None = None) -> str:
    """
    Wrap an event in an RFC 3164 syslog frame.

    The header is required so Wazuh pre-decoding can extract the program name
    (`netaudit`) and hand the JSON body to the decoder in
    integrations/wazuh/decoders/netaudit_decoders.xml.
    """
    host = hostname or socket.gethostname().split(".")[0]
    stamp = datetime.now().strftime("%b %d %H:%M:%S")
    if stamp[4] == "0":  # RFC 3164 pads single-digit days with a space
        stamp = stamp[:4] + " " + stamp[5:]
    body = json.dumps(event, ensure_ascii=False)
    return f"<{SYSLOG_PRI}>{stamp} {host} {SYSLOG_TAG}: {body}"


def send_wazuh_events_syslog(
    events: list[dict[str, Any]],
    host: str,
    port: int = 514,
    protocol: str = "udp",
    hostname: str | None = None,
) -> int:
    """Send raw events as syslog-framed JSON. Returns number of messages sent."""
    proto = protocol.lower()
    lines = [format_syslog_line(event, hostname=hostname) for event in events]
    if not lines:
        return 0

    if proto == "tcp":
        with socket.create_connection((host, port), timeout=10) as sock:
            for line in lines:
                sock.sendall(line.encode("utf-8") + b"\n")
        return len(lines)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            sock.sendto(line.encode("utf-8"), (host, port))
    finally:
        sock.close()
    return len(lines)


def send_wazuh_syslog(
    findings: list[Finding],
    host: str,
    port: int = 514,
    protocol: str = "udp",
) -> int:
    """Send findings as syslog-framed JSON to a Wazuh manager / syslog collector."""
    return send_wazuh_events_syslog(
        [finding_to_wazuh_event(f) for f in findings], host, port=port, protocol=protocol
    )


def send_wazuh_api(
    findings: list[Finding],
    base_url: str,
    user: str,
    password: str,
    verify_ssl: bool = False,
) -> dict[str, Any]:
    """
    Authenticate to the Wazuh API and try to POST events.

    Wazuh 4.x has no universal REST endpoint for injecting arbitrary JSON, so
    this is a connectivity/credential check first and an ingest attempt second.
    The supported ingest paths stay NDJSON + agent localfile, or syslog.
    """
    base = base_url.rstrip("/")
    auth_url = f"{base}/security/user/authenticate"
    req = request.Request(auth_url, method="GET")

    import base64

    token_hdr = base64.b64encode(f"{user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token_hdr}")

    ctx = None
    if not verify_ssl:
        import ssl

        ctx = ssl._create_unverified_context()  # noqa: S323 - self-signed manager certs

    try:
        with request.urlopen(req, context=ctx, timeout=30) as resp:
            auth_body = json.loads(resp.read().decode())
        token = auth_body.get("data", {}).get("token")
        if not token:
            raise RuntimeError(f"No token in Wazuh auth response: {auth_body}")
    except error.HTTPError as exc:
        raise RuntimeError(f"Wazuh auth failed: HTTP {exc.code}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Wazuh API unreachable: {exc.reason}") from exc

    events = [finding_to_wazuh_event(f) for f in findings]
    events_url = f"{base}/events"
    payload = json.dumps({"events": events}).encode("utf-8")
    ev_req = request.Request(events_url, data=payload, method="POST")
    ev_req.add_header("Authorization", f"Bearer {token}")
    ev_req.add_header("Content-Type", "application/json")

    try:
        with request.urlopen(ev_req, context=ctx, timeout=30) as resp:
            body = resp.read().decode()
            return {"ok": True, "status": resp.status, "body": body, "count": len(events)}
    except error.HTTPError as exc:
        if exc.code in (404, 405):
            return {
                "ok": False,
                "authenticated": True,
                "count": len(events),
                "message": (
                    "API login OK, but /events is not available on this manager. "
                    "Use --wazuh-file (agent localfile) or --wazuh-syslog instead."
                ),
                "events": events,
            }
        raise RuntimeError(f"Wazuh /events failed: HTTP {exc.code}") from exc
