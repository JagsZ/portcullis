# 🏰 Portcullis

**Know which gate is open.**

Troy didn't fall to a siege — it fell to an open gate. In the AI era, the
Greek army never leaves: automated bots scan the entire internet 24/7,
probing for one open gate on your machine. **Portcullis** is a one-command
self-audit that tells you which gates are open — and how to close them.

It checks the most common ways into a personal machine, prints and saves a
report, then offers to fix issues. **Safe fixes apply on your confirmation;
risky ones (firewall, service, or encryption changes) are only printed with a
warning — never auto-run.** Nothing changes without your yes, and it never
runs a fix that could lock you out.

---

## Quick start

```bash
git clone https://github.com/<you>/portcullis
cd portcullis
less portcullis          # read it first — it's a security tool you'll run as root
sudo bash portcullis     # full audit (recommended)
```

Prefer a read-only run with no prompts:

```bash
bash portcullis --report-only
```

## What it checks

| Gate | Check |
|------|-------|
| 🚪 Open ports | Sensitive services (SSH, RDP, SMB, DBs) listening beyond localhost |
| 🧱 Firewall | Host firewall enabled (ufw / firewalld / macOS Application Firewall) |
| 🔐 Disk encryption | LUKS (Linux) / FileVault (macOS) |
| 🔑 SSH config | Password login & root login in `sshd_config` |
| 🩹 Updates | Pending OS/package updates (apt / dnf / softwareupdate) |
| 📄 SSH keys | Private key file permissions (auto-fixable) |
| 👀 Startup items | Auto-start entries to review (where infostealers hide) |

## Usage

```
sudo bash portcullis           Full audit (recommended)
bash portcullis                Limited audit (some checks need root)
bash portcullis --report-only  Audit + report only, no prompts
bash portcullis -h | --help    Show help
bash portcullis -V | --version Show version
```

**Exit codes:** `0` clean · `1` findings need attention · `2` usage error
(handy for cron/CI).

## How fixes work

- **Safe fixes** (e.g. tightening SSH key permissions) — Portcullis asks, and
  applies them only if you say yes.
- **Risky fixes** (firewall, disabling services, enabling disk encryption,
  changing `sshd_config`) — Portcullis **prints the exact command plus a
  warning** and leaves it to you. These can drop connections or lock you out,
  so you stay in control.

## Supported systems

- ✅ **Linux** (Debian/Ubuntu, Fedora/RHEL — ufw or firewalld)
- ✅ **macOS**
- 🚧 **Windows** — see [`windows/portcullis.ps1`](windows/portcullis.ps1) (beta, not yet fully tested)

## A note on trust

Portcullis is meant to be run with `sudo`, so **read the script before you run
it** — it's short and deliberately unobfuscated. That's the same principle it
audits for: don't blindly trust what you run. For the same reason, this project
avoids `curl | sudo bash` installers.

## Disclaimer

Portcullis covers common personal-security hygiene — it is **not** a full
security audit or a replacement for professional assessment, EDR, or your
organization's policies. Always review a suggested fix before running it.

## License

MIT — see [LICENSE](LICENSE).
