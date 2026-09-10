# scanmedaddy

Network audit and config backup over SSH (FortiGate 120G, SCALANCE XC208, Cisco) with Wazuh export. Beta — not a supported public product. Required: Python 3. Do not use against systems you do not own.

```powershell
pip install -e ".[dev]"
netaudit backup --demo
netaudit audit --file samples\fg-120g-01.cfg --platform fortigate --export reports\fg-audit.md
```

Live devices: copy `.env.example` to `.env`, then `netaudit backup --dry-run` and `netaudit backup`.
