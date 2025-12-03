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
| `--dashboard MODE`         | Live visualization: `tui`, `web`, `both`, `none` (default: `none`).         |
| `--dashboard-port PORT`    | Web dashboard port (default: `8042`).                                       |
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

**Live collection with real-time TUI dashboard:**

./sequoia_forensic.sh --no-image-ok --dashboard tui --out ~/Desktop/case_live

**Live collection with web dashboard (view in browser):**

./sequoia_forensic.sh --no-image-ok --dashboard web --dashboard-port 8042 --out ~/Desktop/case_web
# Open browser to http://localhost:8042/dashboard.html


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
  - Generates artifact integrity manifest with SHA-256 hashes for chain-of-custody verification.

- **Live Dashboard System (NEW)**
  - Real-time TUI dashboard with progress bars, stats, and event feed.
  - Web-based dashboard accessible via browser (default port: 8042).
  - Live metrics: files collected, total size, elapsed time, current step.
  - Recent events log with color-coded status indicators.

- **Security Hardening (NEW)**
  - Input validation prevents path traversal attacks.
  - Shell injection vulnerability fixes in imaging workflow.
  - Secure argument handling throughout collection pipeline.

- **Performance Optimizations (NEW)**
  - Tool availability caching for faster runtime detection.
  - Batched `lsof` calls (100x faster unsigned process detection).
  - I/O priority control with `ionice` when available.
  - Limited unified log plaintext to 500k lines max (prevents multi-GB files).

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

## Recent Updates

### v1.7.0 - Live Dashboard & Security Hardening (Latest)
- **Live Dashboard System**: Real-time TUI and web-based collection monitoring
- **Security Fixes**: Path traversal prevention, shell injection patches
- **Performance**: 100x faster unsigned process detection via batched lsof calls
- **Artifact Integrity**: SHA-256 manifest generation for chain-of-custody
- **I/O Optimization**: ionice support, unified log output capping

### v1.6.1 - Unstoppable Receipt
- Hardened error handling with non-fatal collectors
- Added run-status receipt file with start/end timestamps
- Improved stability in Unified Logs and Suspicious Processes collection

---

## Documentation

For detailed architecture, development guidelines, and troubleshooting, see [HINTS.md](./HINTS.md).

