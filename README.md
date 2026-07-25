# scanmedaddy

> **BETA**  
> It is published as a **beta** reference - not a supported public product. Do not use against systems you do not own or administer.

CLI tool for **configuration backup** of routers/switches/firewalls over SSH, **change diffing**, **standards validation**, and **detection of unsafe settings**, with **Wazuh** integration.

Production: **FortiGate 120G**, **SCALANCE XC208**, alert export to SIEM.

## Features

| Feature | Description |
|---------|-------------|
| **SSH backup** | FortiGate (`show full-configuration`), SCALANCE XC208 (`show running-config`) |
| **Versioning** | Snapshots under `backups/<device>/<timestamp>.cfg` + `index.json` |
| **Diff** | Unified diff between backups |
| **Audit** | Per-platform rules: any/any, weak SNMP, missing NTP/syslog, telnet, HTTP, ... |
| **Export** | Markdown + CSV |
| **Secret management** | No passwords in `inventory.yaml`: env / `.env` / file / Windows Credential Manager / keyring |
| **Dry run** | Validate inventory, credentials and reachability without touching the store |
| **Scheduling** | Task Scheduler and cron wrappers, retries, alert when SSH fails |
| **Wazuh** | NDJSON for the agent or syslog, decoder + rules + dashboard queries + `wazuh-logtest` harness |

## Platforms

| `platform` in inventory | Device | Backup command |
|-------------------------|--------|----------------|
| `fortigate` / `fortios` | **FortiGate 120G** (and other FG models) | `show full-configuration \| grep .` |
| `scalance_xc` / `scalance` | **SCALANCE XC208** (XC-200) | `show running-config` |
| `cisco_ios` / `cisco_asa` | Cisco | `show running-config` |

## Quick start (demo without hardware)

```powershell
cd C:\Users\marci\Projects\network-audit-backup
.\.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest

netaudit backup --demo

# FortiGate 120G sample
netaudit audit --file samples\fg-120g-01.cfg --platform fortigate `
  --export reports\fg-audit.md --wazuh-file reports\wazuh-netaudit.json

# SCALANCE XC208 sample
netaudit audit --file samples\scalance-xc208-01.cfg --platform scalance_xc `
  --export reports\xc208-audit.md --wazuh-file reports\wazuh-netaudit.json
```

## Credentials (nothing secret in the inventory)

`inventory.yaml` stores a *reference*, resolved at runtime:

| Reference | Source |
|-----------|--------|
| `env:FG_120G_01_PASSWORD` | Environment variable (also read from `.env`) |
| `${FG_120G_01_PASSWORD}` | Same, inline form |
| `file:C:\secrets\fg.txt` | First line of a file |
| `wincred:netaudit/core-sw-01` | Windows Credential Manager (generic credential) |
| `keyring:netaudit/core-sw-01` | `keyring` package |
| `prompt` | Ask interactively (rejected in scheduled runs) |
| *(empty)* | Falls back to `NETAUDIT_<DEVICE>_PASSWORD` |

```powershell
copy .env.example .env      # then fill it in; .env is git-ignored
netaudit secrets            # shows the source of every credential, never the value
```

Store a credential in Windows Credential Manager instead of `.env`:

```powershell
cmdkey /generic:netaudit/core-sw-01 /user:admin /pass
```

`netaudit secrets` exits non-zero if anything is unresolved **or** if a password
is still hardcoded in the inventory, so it works as a pre-flight gate in CI.

## FortiGate 120G + SCALANCE XC208 (live devices)

```yaml
devices:
  - name: fg-120g-01
    host: 192.168.10.1
    device_type: firewall
    platform: fortigate
    username: admin
    password: env:FG_120G_01_PASSWORD
    port: 22
    tags: [edge, fortigate]

  - name: scalance-xc208-01
    host: 192.168.20.10
    device_type: switch
    platform: scalance_xc
    username: admin
    password: env:SCALANCE_XC208_01_PASSWORD
    port: 22
    tags: [ot, siemens]
```

```powershell
netaudit backup --dry-run          # credentials + TCP reachability, writes nothing
netaudit backup                    # with retries; --tag ot limits the scope
netaudit audit --export reports\audit.md --csv reports\audit.csv `
  --wazuh-file reports\wazuh-netaudit.json
netaudit diff fg-120g-01
```

## Scheduled runs

`netaudit run` is the unattended cycle: backup with retries, audit the fresh
snapshots, write `reports/audit.{md,csv}` and `reports/run-report.json`, and
push findings plus failure alerts to Wazuh.

```powershell
netaudit run --wazuh-file C:\ProgramData\netaudit\wazuh-netaudit.json
```

Exit codes: `0` clean, `1` at least one backup failed, `2` critical/high findings.

| Wrapper | Platform | Purpose |
|---------|----------|---------|
| `scripts\scheduled-backup.ps1` | Windows | Activates the venv, logs with rotation, propagates the exit code |
| `scripts\install-scheduled-task.ps1` | Windows | Registers/removes the Task Scheduler job |
| `scripts/scheduled-backup.sh` | Linux | Same wrapper for cron |
| `scripts/netaudit.cron.example` | Linux | Nightly full run + hourly dry run |

```powershell
# daily 02:30, alerts written where the Wazuh agent reads them
.\scripts\install-scheduled-task.ps1 -At 02:30 `
  -WazuhFile C:\ProgramData\netaudit\wazuh-netaudit.json
Start-ScheduledTask -TaskName netaudit-backup
Get-ScheduledTaskInfo -TaskName netaudit-backup
```

When SSH fails, retries are attempted (`--retries`, `--retry-delay`) and a
`backup_failed` event is emitted with the device, platform, attempt count and
error, followed by a `run_summary` event. That is what raises the SIEM alert -
a silent backup job is the failure mode this avoids.

## Wazuh (end to end)

```
netaudit audit/run
   |
   |-- wazuh-file   -> NDJSON -> agent localfile (json) -> built-in decoder -> rule 100500
   `-- wazuh-syslog -> RFC 3164 syslog -> manager -> decoder "netaudit" -> rule 100501
```

1. Produce events: `netaudit run --wazuh-file C:\ProgramData\netaudit\wazuh-netaudit.json`
2. Agent: add the `<localfile>` block from `integrations/wazuh/ossec-localfile.conf.snippet`.
3. Manager: install `integrations/wazuh/decoders/netaudit_decoders.xml` and
   `integrations/wazuh/rules/netaudit_rules.xml`, then restart.
4. Verify: `sudo integrations/wazuh/logtest/run-logtest.sh` feeds
   `logtest/samples.log` through `wazuh-logtest` and fails if any line does not
   match a `1005xx` rule. Regenerate samples with `netaudit wazuh-samples`.
5. Dashboard: queries and visualisations in
   `integrations/wazuh/queries/dashboard-queries.md`; full setup notes in
   `integrations/wazuh/README.md`.

Alert levels: critical finding 12, high 10, medium 7, low/info 5/3, backup
failure 10, config drift 7, three failures for one device in 24h 12.

## Audit rules (summary)

**FortiGate:** `FG-POLICY-ANY-ANY`, `FG-SNMP-WEAK`, `FG-NTP-MISSING`, `FG-SYSLOG-MISSING`, `FG-TELNET-ADMIN`, `FG-HTTP-ADMIN`, ...

**SCALANCE XC208:** `SC-ACL-PERMIT-ANY`, `SC-SNMP-WEAK`, `SC-NTP-MISSING`, `SC-SYSLOG-MISSING`, `SC-TELNET-ENABLED`, ...

**Cisco:** `ACL-PERMIT-ANY`, weak SNMP, missing NTP/syslog, telnet, type 7, VTY without ACL, ...

Rule files: `netaudit/rules/{default,fortigate,scalance}.yaml`

## Tests

```powershell
pytest -q
```

Covers audit rules per platform, credential resolution, retry/dry-run
behaviour, the Wazuh event schema, and the shipped decoder/rules XML (rule IDs,
field names and description placeholders are checked against real events).

Manual on-the-wire check of the syslog transport:

```powershell
python tests\manual\verify_syslog_receive.py
```
