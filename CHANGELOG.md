# Changelog

## v1.0.0
- First release. Linux + macOS self-audit: firewall, exposed ports, disk
  encryption, SSH config, pending updates, SSH key permissions, startup items.
- Interactive fixes: safe fixes apply on confirmation; risky ones are printed
  with a warning, never auto-run.
- Flags: `--report-only`, `--help`, `--version`. Exit codes: 0/1/2.
- Windows PowerShell script included as beta (`windows/portcullis.ps1`).
