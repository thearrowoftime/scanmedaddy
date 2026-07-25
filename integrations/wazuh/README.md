# Wazuh integration for netaudit

End-to-end path: netaudit emits JSON events -> Wazuh decodes them -> rules
`1005xx` raise alerts -> dashboard queries surface them.

```
netaudit audit/run
   |
   |-- --wazuh-file  -> NDJSON file -> agent localfile (log_format=json) -> built-in "json" decoder -> rule 100500
   |
   `-- --wazuh-syslog -> RFC 3164 syslog -> manager remote/syslog -> decoder "netaudit" -> rule 100501
```

## Files

| File | Goes to | Purpose |
|------|---------|---------|
| `decoders/netaudit_decoders.xml` | manager `/var/ossec/etc/decoders/` | Decodes the syslog transport |
| `rules/netaudit_rules.xml` | manager `/var/ossec/etc/rules/` | Alert rules `100500`-`100540` |
| `ossec-localfile.conf.snippet` | agent `ossec.conf` | Reads the NDJSON file |
| `logtest/run-logtest.sh` | manager (run manually) | Verifies decoder + rules |
| `logtest/samples.log` | manager (input) | Sample events, regenerate with `netaudit wazuh-samples` |
| `queries/dashboard-queries.md` | dashboard | DQL queries, visualisations, alert monitor |

## 1. Produce events

```powershell
# findings only
netaudit audit --wazuh-file reports\wazuh-netaudit.json

# full scheduled cycle: backup (with retries) + audit + alerts on SSH failure
netaudit run --wazuh-file C:\ProgramData\netaudit\wazuh-netaudit.json
```

Event shape (one JSON object per line):

```json
{"timestamp":"2026-07-25T13:20:11.412Z","integration":"netaudit","netaudit":{"event_type":"finding","rule_id":"FG-POLICY-ANY-ANY","severity":"critical","device":"fg-120g-01","detail":"Policy 'allow-all-any-any' accepts src/dst all with service ALL","wazuh_level":12}}
{"timestamp":"2026-07-25T13:20:11.413Z","integration":"netaudit","netaudit":{"event_type":"backup_failed","rule_id":"NETAUDIT-BACKUP-FAILED","severity":"high","device":"scalance-xc208-01","detail":"Config backup failed ...","attempts":3,"wazuh_level":10}}
```

`event_type` is one of `finding`, `backup_failed`, `config_changed`, `run_summary`.

## 2. Install on the manager

```bash
sudo install -o wazuh -g wazuh -m 0640 decoders/netaudit_decoders.xml /var/ossec/etc/decoders/
sudo install -o wazuh -g wazuh -m 0640 rules/netaudit_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

## 3. Install on the agent

Add the `<localfile>` block from `ossec-localfile.conf.snippet` to the agent's
`ossec.conf`, adjust the path, restart the agent.

## 4. Verify with wazuh-logtest

```bash
# on the manager
sudo ./logtest/run-logtest.sh
```

The script feeds every line of `samples.log` into `wazuh-logtest` and fails if
any line does not match a `1005xx` rule. Expected output per line:

```
**Phase 3: Completed filtering (rules).
        id: '100510'
        level: '12'
        description: 'netaudit CRITICAL: FortiGate firewall policy accepts all to all on fg-120g-01'
```

Regenerate samples from your own configs:

```powershell
netaudit wazuh-samples --file samples\fg-120g-01.cfg
netaudit wazuh-samples --file samples\scalance-xc208-01.cfg --platform scalance_xc `
  --out integrations\wazuh\logtest\samples-scalance.log
```

## 5. Optional: syslog instead of a file

```powershell
netaudit audit --wazuh-syslog 192.168.1.50 --wazuh-syslog-port 514
```

Requires the `<remote><connection>syslog</connection>` block on the manager
(see the snippet) and the decoder from step 2.

## 6. Optional: API credential check

```powershell
netaudit audit --wazuh-api https://WAZUH-MANAGER:55000 --wazuh-user wazuh --wazuh-pass '***'
```

Wazuh 4.x has no general-purpose event injection endpoint, so this validates
credentials and reports back that the file/syslog path should be used for ingest.

## Rule reference

| Rule | Level | Fires on |
|------|------:|----------|
| 100500 / 100501 | 3 | Base rules (file / syslog transport) |
| 100510 | 12 | `severity: critical` finding |
| 100511 | 10 | `severity: high` finding |
| 100512 | 7 | `severity: medium` finding |
| 100513 | 5 | `severity: low` or `info` finding |
| 100520 | 12 | Permissive policy/ACL (`FG-POLICY-ANY-ANY`, `ACL-PERMIT-ANY`, `SC-ACL-PERMIT-ANY`) |
| 100521 | 10 | Device not shipping syslog |
| 100522 | 10 | Telnet management enabled |
| 100530 | 10 | Backup failed for a device |
| 100531 | 7 | Config changed since previous snapshot |
| 100532 | 3 | Run summary |
| 100533 | 10 | Run summary containing failures |
| 100540 | 12 | 3+ backup failures for the same device within 24h |

Rule IDs stay in the user range (100000+) so they never collide with the
upstream ruleset. Dashboard queries live in `queries/dashboard-queries.md`.
