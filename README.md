# Sequoia Forensic

Acquisition-first forensic collector for macOS Sequoia.

## Features & Capabilities

The Sequoia Forensic Collector is a host-based acquisition-first script for macOS Sequoia.  
It’s designed for both live triage **and** offline analysis from a mounted disk or LiveUSB boot.

## Quick Start

### Clone the repo and run the script against the host system:
git clone https://github.com/sydlexxia/sequoia-forensic.git
cd sequoia-forensic
chmod +x sequoia_forensic.sh
./sequoia_forensic.sh --out /tmp/case

## Usage

./sequoia_forensic.sh --help      # for the latest options.  


### Command-line Flags

| Flag / Option              | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `--out DIR`                | Output directory. All collected artifacts and reports are stored here.      |
| `--no-image-ok`            | Skip disk imaging if no device selected. Collects logs/artifacts only.      |
| `--image DEVICE`           | Force a specific device for imaging (e.g., `/dev/disk2`).                   |
| `--fast`                   | Enable fast mode (limits deep scans, quicker results).                      |
| `--since N`                | Time window for logs/events (e.g., `48h`, `7d`, `30d`). Default: `7d`.      |
| `--skip-logs`              | Bypass Unified Log plaintext extraction (still collects `.logarchive`).     |
| `--ask-skip-logs`          | Prompt interactively to bypass Unified Log plaintext.                       |
| `--encrypt METHOD:KEY`     | Supported: `age:/path/to/key.pub`, `gpg:ID`, `openssl:cert.pem`.            |
| `--webhook URL`            | Send results to a Discord webhook (JSON + HTML report).                     |
| `--debug`                  | Enable debug traps and verbose logging.                                     |
| `--help`                   | Show usage information.                                                     |


### Typical Workflows

**Fast live triage (minimal impact, skips imaging):**

./sequoia_forensic.sh --no-image-ok --fast --skip-logs --out ~/Desktop/case_fast

**Full acquisition (disk image + logs, requires sudo):**

sudo ./sequoia_forensic.sh --out /cases/case001

**Encrypted results with public key (age):**

./sequoia_forensic.sh --no-image-ok --encrypt age:/path/to/pubkey.txt --out ~/cases/encase

**Send results to Discord (lab/team triage):**

./sequoia_forensic.sh --no-image-ok --webhook https://discord.com/api/webhooks/... --out ~/Desktop/case_discord


### Common Options
  --no-image-ok : Skip full disk imaging (just collect logs, processes, artifacts).

  --since 7d    : Collect events from the last 7 days (supports 12h, 48h, 30d).

  --skip-logs   : Bypass Unified Log plaintext extraction (still saves .logarchive).

  --fast        : Faster scan mode (limits deep checks, still collects core data).

  --encrypt age /path/to/key.pub : Encrypt results with age, gpg, or openssl.

### Example: Live triage with fast mode, skip logs
  ./sequoia_forensic.sh --no-image-ok --fast --skip-logs --out ~/Desktop/forensics_case

### Example: Full acquisition + image hashing
  sudo ./sequoia_forensic.sh --out /cases/case001

All collected evidence and reports will be placed in the chosen --out directory.
At the end you’ll find:
  report.html (human-readable report)
  capabilities.json (machine-readable environment card)
  run_status.txt (receipt with start/end/exit code)


### Core Capabilities
- **Acquisition-first workflow**  
  - Collects disk, logs, artifacts before analysis (to avoid polluting evidence).
  - Images entire disks with `ddrescue` or `dd` (if available).
  - Hashes acquired images (SHA256).

- **Filesystem & Access Monitoring**
  - Collects recent file/folder access via FSEvents.
  - Optionally include/exclude system files.
  - Records recent sudo use.
  - Detects login/reboot events, USB mounts, and network connections.

- **Process & Persistence Checks**
  - Identifies suspicious processes (from `/tmp`, unsigned, reverse shells).
  - Scans for suspicious cron jobs and LaunchAgents/Daemons.
  - Flags unusual dotfiles in user homes.
  - Checks for rootkits using `chkrootkit` / `rkhunter` if installed.

- **Network & Sharing Audit**
  - Captures SMB, Bluetooth sharing, and open network sockets.
  - Saves snapshots of current listening ports (`lsof`, `netstat`).

- **Logging & Unified Events**
  - Collects Unified Logs as `.logarchive`.
  - Optional plaintext extraction (time-limited, bypassable at runtime).
  - Copies standard system logs and per-volume logs.

### Reporting & Output
- **Report Formats**  
  - Human-readable **HTML5 report** with sections per artifact.
  - JSON `capabilities.json` environment card for machine-readable state.
  - Discord webhook integration for remote notifications (optional).
- **Chain of Custody**  
  - Interactive device picker with chain-of-custody block.
  - Tracks acquisition metadata and operator inputs.
- **Encryption Support**  
  - Can encrypt collected results with `age`, `gpg`, or `openssl` public key.

### Investigator UX
- **Interactive Controls**  
  - Device selection prompt for imaging.
  - Runtime option to bypass heavy steps (e.g., Unified logs).
- **Safety Rails**  
  - Progress bar with ETA on long-running steps.
  - Hardened against hangs (timeouts on heavy steps).
  - Non-fatal collectors: one failure never aborts the run.
- **Environment Card**  
  - Captures available tooling (e.g., `ddrescue`, `lsof`, `osquery`).
  - Preserves a snapshot of the runtime environment in the report.

---

> **Current Release:** `v1.6.1-unstoppable-receipt`  
> This release hardens error handling, adds a run-status receipt file, and improves stability in Unified Logs and Suspicious Processes collection.

