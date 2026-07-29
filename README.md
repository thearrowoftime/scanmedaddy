# scanmedaddy

[![CI](https://github.com/thearrowoftime/scanmedaddy/actions/workflows/ci.yml/badge.svg)](https://github.com/thearrowoftime/scanmedaddy/actions/workflows/ci.yml)

> **BETA**  
> It is published as a **beta** reference - not a supported public product. Do not use against systems you do not own or administer.

CLI tool for **configuration backup** of routers/switches/firewalls over SSH, **change diffing**, **standards validation**, and **detection of unsafe settings**, with **Wazuh** integration.

Production: **FortiGate 120G**, **SCALANCE XC208**, alert export to SIEM.

## Features

| Feature | Description |
|---------|-------------|
| **SSH backup** | FortiGate (`show full-configuration`), SCALANCE XC208 (`show running-config`) |
| **SSH trust** | Host keys pinned in `known_hosts`, key auth, jump host, critical alert when a key changes |
| **Versioning** | Snapshots under `backups/<device>/<timestamp>.cfg` + `index.json` |
| **Diff** | Unified diff between backups |
| **Audit** | Per-platform rules: any/any, weak SNMP, missing NTP/syslog, telnet, HTTP, ... |
| **Inventory facts** | Model, firmware, serial, VLANs, interfaces, admins - plus an outdated firmware rule |
| **Baseline drift** | Compare against an approved golden config, section by section |
| **Compliance score** | Score and trend per device, mapped to CIS Controls v8 and IEC 62443-3-3 |
| **Export** | Markdown + CSV |
| **Secret management** | No passwords in `inventory.yaml`: env / `.env` / file / Windows Credential Manager / keyring |
| **Dry run** | Validate inventory, credentials, host key pinning and reachability without touching the store |
| **Scheduling** | Task Scheduler and cron wrappers, retries, alert when SSH fails |
| **Wazuh** | NDJSON for the agent or syslog, decoder + rules + dashboard queries + `wazuh-logtest` harness |
| **Active response** | Wazuh sees a config change and netaudit pulls the evidence immediately |

## Platforms

| `platform` in inventory | Device | Backup command |
|-------------------------|--------|----------------|
| `fortigate` / `fortios` | **FortiGate 120G** (and other FG models) | `show full-configuration \| grep .` |
| `scalance_xc` / `scalance` | **SCALANCE XC208** (XC-200) | `show running-config` |
| `cisco_ios` / `cisco_asa` | Cisco | `show running-config` |

## Commands

| Command | Purpose |
|---------|---------|
| `netaudit init` | Create an example `inventory.yaml` and the folder layout |
| `netaudit backup` | Pull configs over SSH (`--dry-run` validates, `--demo` imports the samples) |
| `netaudit run` | Unattended cycle: backup, audit, export, alert |
| `netaudit respond` | Alert-triggered backup + diff + audit (used by Wazuh active response) |
| `netaudit diff` | Unified diff between two snapshots |
| `netaudit audit` | Security and standards findings, including firmware level |
| `netaudit baseline` | Drift from an approved golden config |
| `netaudit compliance` | Score per device with trend, mapped to CIS / IEC 62443 |
| `netaudit facts` | Model, firmware, serial, VLANs, interfaces, admins |
| `netaudit secrets` | Show how every credential resolves, without printing values |
| `netaudit hostkeys` | List pinned SSH host keys, `--forget` one after a replacement |
| `netaudit list` / `show` | Browse stored snapshots |
| `netaudit import-config` | Store a local config file as a snapshot |
| `netaudit wazuh-samples` | Generate `wazuh-logtest` input lines |

Exit codes are meant for schedulers and pipelines:

| Command | 0 | 1 | 2 | 3 |
|---------|---|---|---|---|
| `backup` | all devices backed up | a backup failed | - | - |
| `run` | clean | a backup failed | critical/high findings | - |
| `respond` | no change | backup failed | critical/high findings | config changed |
| `audit` / `baseline` | no serious findings | nothing to audit | critical/high findings | - |
| `compliance` | above the threshold | no backups yet | below `--min-score` | - |
| `secrets` | everything resolves | unresolved or hardcoded credential | - | - |

## Quick start (demo without hardware)

```powershell
git clone https://github.com/thearrowoftime/scanmedaddy.git
cd scanmedaddy
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

netaudit backup --demo

# FortiGate 120G sample
netaudit audit --file samples\fg-120g-01.cfg --platform fortigate `
  --export reports\fg-audit.md --wazuh-file reports\wazuh-netaudit.json

# SCALANCE XC208 sample
netaudit audit --file samples\scalance-xc208-01.cfg --platform scalance_xc `
  --export reports\xc208-audit.md --wazuh-file reports\wazuh-netaudit.json

# what these boxes are, and whether their firmware is current
netaudit facts

# drift from the approved template, and the resulting score
netaudit baseline --profile baselines\fortigate-lab.yaml
netaudit compliance --baseline baselines\fortigate-lab.yaml --export reports\compliance.md
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

  # OT switch reached through a bastion, authenticated with a key
  - name: scalance-xc208-01
    host: 192.168.20.10
    device_type: switch
    platform: scalance_xc
    username: admin
    key_file: C:\Users\marci\.ssh\id_ed25519
    key_passphrase: env:SSH_KEY_PASSPHRASE
    port: 22
    tags: [ot, siemens]
    jump:
      host: 10.0.0.5
      username: netops
      password: env:JUMP_PASSWORD
```

```powershell
netaudit backup --dry-run          # credentials, host key pinning, TCP reachability
netaudit backup                    # with retries; --tag ot limits the scope
netaudit audit --export reports\audit.md --csv reports\audit.csv `
  --wazuh-file reports\wazuh-netaudit.json
netaudit diff fg-120g-01
```

## SSH trust: host keys, keys, jump hosts

A tool that flags telnet should not itself accept any key it is handed. Device
keys are verified against `.netaudit\known_hosts`:

| Situation | What happens |
|-----------|--------------|
| First connection | Key is pinned, `host_key_learned` event (info) |
| Key matches the pin | Normal backup |
| Key changed | Backup **aborts**, `host_key_changed` event, Wazuh rule `100550` at level 14 |
| Not pinned yet, `--strict-host-keys` | Device is skipped as `blocked`, `host_key_unpinned` event |

A changed key is never retried - retrying only hides it. Pin keys once
interactively, then enforce in the scheduled run:

```powershell
netaudit backup --dry-run        # reports which devices are pinned
netaudit backup                  # pins anything new and reports it
netaudit hostkeys                # list pinned fingerprints
netaudit run --strict-host-keys  # scheduled runs refuse unpinned devices
netaudit hostkeys --forget 192.168.20.10   # after a legitimate replacement
```

Authentication accepts a private key (`key_file`, with `key_passphrase` resolved
like any other secret) and reaching devices through a bastion is a `jump:` block
in the inventory - the usual case for an OT segment where the switch is not
routable from the management host.

## Inventory facts and firmware

```powershell
netaudit facts --json reports\facts.json
```

Model, firmware, serial, VLANs, interfaces and admin accounts are read from the
snapshots you already collect, so this needs no extra device access. FortiOS
carries its version in the `#config-version` header; for SCALANCE the version
comes from the snapshot header comment, so capture `show version` output with the
config if you want patch level audited there.

`netaudit/rules/firmware.yaml` holds the minimum accepted version per platform.
Anything older becomes an `FW-OUTDATED` finding (Wazuh rule `100571`) that flows
into the same reports and alerts as every other finding. Keep the file in step
with FortiGuard PSIRT and Siemens ProductCERT advisories, and with what your
change board actually approved.

## Baseline (golden config) and compliance score

Rules answer "is this configured securely". A baseline answers "does this still
match what we approved". Only the sections listed in the profile are compared,
so hostnames and addresses never show up as drift.

```powershell
netaudit baseline --profile baselines\fortigate-lab.yaml --export reports\drift.md
```

| Finding | Meaning |
|---------|---------|
| `BASELINE-MISSING` | An approved section is absent from the device |
| `BASELINE-DRIFT` | The section exists but its contents differ |
| `BASELINE-EXTRA` | The device has a section the baseline does not define |

`netaudit compliance` turns findings into a number: each device starts at 100 and
loses 25 per critical, 10 per high, 4 per medium and 1 per low finding. Scores are
recorded in `reports/compliance-history.json`, so the next run shows the trend,
and findings are grouped by CIS Controls v8 safeguard and IEC 62443-3-3 system
requirement (`netaudit/rules/frameworks.yaml`). That mapping is indicative -
useful for steering remediation and talking to an auditor, not a certification.
Rules without a mapping are listed rather than silently dropped.

```powershell
netaudit compliance --baseline baselines\fortigate-lab.yaml `
  --export reports\compliance.md --csv reports\scores.csv --min-score 60
```

`--min-score` exits with code 2 when any device is below the threshold, which
makes it usable as a gate in a pipeline.

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
failure 10, config drift 7, three failures for one device in 24h 12, **SSH host
key changed 14**.

## Active response: Wazuh asks netaudit for evidence

The steps above push data into Wazuh. This is the other direction - the SIEM sees
a device report a configuration change and netaudit immediately produces the
proof, instead of waiting for the nightly backup:

```
FortiGate / Cisco syslog "config changed"  ->  rule 100580-100582
netaudit host key changed                  ->  rule 100550
                                                 |
                       active response: netaudit-ar.py
                                                 |
                       netaudit respond --device <name>
                                                 |
       fresh backup + diff + audit  ->  events back into Wazuh
```

```powershell
# what the active response runs (works standalone too)
netaudit respond --device fg-120g-01 --reason "wazuh rule 100580" `
  --wazuh-file C:\ProgramData\netaudit\wazuh-netaudit.json --diff-out reports\ar-diff.md
```

Exit codes: `0` no change, `1` backup failed, `2` critical/high findings,
`3` configuration changed. Setup, the mapping from Wazuh agents to inventory
devices, and how to test the script by hand are in
`integrations/wazuh/README.md`.

## Audit rules (summary)

**FortiGate:** `FG-POLICY-ANY-ANY`, `FG-SNMP-WEAK`, `FG-NTP-MISSING`, `FG-SYSLOG-MISSING`, `FG-TELNET-ADMIN`, `FG-HTTP-ADMIN`, ...

**SCALANCE XC208:** `SC-ACL-PERMIT-ANY`, `SC-SNMP-WEAK`, `SC-NTP-MISSING`, `SC-SYSLOG-MISSING`, `SC-TELNET-ENABLED`, ...

**Cisco:** `ACL-PERMIT-ANY`, weak SNMP, missing NTP/syslog, telnet, type 7, VTY without ACL, ...

**Firmware:** `FW-OUTDATED`, `FW-UNKNOWN` — **Baseline:** `BASELINE-DRIFT`, `BASELINE-MISSING`, `BASELINE-EXTRA`

Rule files: `netaudit/rules/{default,fortigate,scalance,firmware}.yaml`,
framework mapping in `netaudit/rules/frameworks.yaml`

## Tests

```powershell
pip install -e ".[dev]"
pytest -q
ruff check .
```

Covers audit rules per platform, credential resolution, retry/dry-run behaviour,
inventory facts and firmware policy, baseline drift, compliance scoring and
history, the Wazuh event schema, and the shipped decoder/rules XML (rule IDs,
field names and description placeholders are checked against real events, and the
active response is checked against rules that actually exist).

The fragile part of any config collector is the terminal handling, so
`tests/fake_ssh.py` runs a real in-process SSH server that imitates FortiGate and
SCALANCE prompts, pager output and a bastion. It exercises prompt detection,
pager acknowledgement, authentication failures, key pinning, key rotation and
jump host tunnelling against the actual paramiko code path rather than a mock.

GitHub Actions runs the same lint and test matrix (Linux and Windows, Python
3.10-3.13) plus an end-to-end demo job that audits the sample configs and checks
the exit codes.

Manual on-the-wire check of the syslog transport:

```powershell
python tests\manual\verify_syslog_receive.py
```

## Repository layout

| Path | Contents |
|------|----------|
| `netaudit/` | Package: SSH backup, store, diff, audit, facts, baseline, compliance, Wazuh, CLI |
| `netaudit/rules/` | Audit rule packs, firmware minimums, framework mapping |
| `baselines/` | Example golden configs and profiles for FortiGate and SCALANCE |
| `samples/` | Intentionally insecure sample configs used by the demo and tests |
| `scripts/` | Task Scheduler and cron wrappers |
| `integrations/wazuh/` | Decoder, rules, active response, dashboard queries, logtest harness |
| `tests/` | Test suite, including the in-process fake SSH server |
| `backups/`, `reports/`, `.netaudit/` | Runtime output: snapshots, reports, pinned host keys (git-ignored) |
