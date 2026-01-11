# 04-network-config-audit
## Innehåll
- `network_configs/` – indata (konfigurationsarkiv + loggar)
- `src/config_audit.ps1` – PowerShell-script för inventering och analys
- `output/security_audit.txt` – huvudrapport
- `output/config_inventory.csv` – inventering av konfigfiler
- `output/log_keyword_counts.csv` – ERROR/FAILED/DENIED per loggfil
- `output/unique_ip_addresses.txt` – unika IP-adresser från .conf
- `output/security_issues.csv` – matchningar på svaga konfigurationer (om ingår)
- `output/baseline_deviations.csv` – avvikelser mot baseline (om ingår)

## Körning
Kör från repo-roten:

```bash
pwsh -File ./src/config_audit.ps1
