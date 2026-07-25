# Wazuh dashboard queries for netaudit

Index pattern: `wazuh-alerts-*`

Decoded JSON fields land under `data.` in alerts, so the dashboard uses
`data.netaudit.*` while the rules XML matches `netaudit.*`. That asymmetry is
normal Wazuh behaviour, not a typo.

## Discover (DQL)

| Goal | Query |
|------|-------|
| Every netaudit event | `rule.groups: netaudit` |
| Critical findings only | `rule.groups: netaudit and data.netaudit.severity: critical` |
| One device | `data.netaudit.device: "fg-120g-01"` |
| FortiGate any/any policies | `data.netaudit.rule_id: "FG-POLICY-ANY-ANY"` |
| SCALANCE XC208 findings | `data.netaudit.rule_id: SC-*` |
| Devices not shipping syslog | `data.netaudit.rule_id: (*SYSLOG-MISSING)` |
| Backup failures | `rule.id: 100530` |
| Repeated backup failures (24h) | `rule.id: 100540` |
| Config drift detected | `rule.id: 100531` |
| Run summaries with failures | `rule.id: 100533` |
| Everything except informational noise | `rule.groups: netaudit and rule.level >= 7` |

## Useful visualisations

1. **Findings by severity** - Pie, split by `data.netaudit.severity`,
   filter `data.netaudit.event_type: finding`.
2. **Findings per device** - Horizontal bar, terms on `data.netaudit.device`,
   ordered by count.
3. **Top violated rules** - Data table, terms on `data.netaudit.rule_id`,
   metric: count.
4. **Backup reliability** - Line chart, `rule.id: (100530 or 100532)` over time,
   split by `rule.id`.
5. **Config drift timeline** - Date histogram on `rule.id: 100531`,
   split by `data.netaudit.device`.

## Alerting (Wazuh dashboard / OpenSearch alerting)

Monitor extract for "backup failed twice in a row":

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "rule.id": "100530" } },
        { "range": { "@timestamp": { "gte": "now-25h" } } }
      ]
    }
  },
  "aggs": {
    "per_device": {
      "terms": { "field": "data.netaudit.device", "size": 20 },
      "aggs": { "failures": { "value_count": { "field": "rule.id" } } }
    }
  }
}
```

Trigger condition: any bucket in `per_device` with `failures >= 2`.

## Sanity check without devices

```powershell
netaudit audit --file samples\fg-120g-01.cfg --platform fortigate `
  --wazuh-file reports\wazuh-netaudit.json
```

Then confirm the agent picked the file up:

```
rule.groups: netaudit and agent.name: "YOUR-AGENT"
```
