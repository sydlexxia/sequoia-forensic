# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sequoia Forensic is a host-based, acquisition-first forensic collector for macOS Sequoia. It's a single-file Bash script (Bash 3.2 compatible) designed for live triage and offline analysis from mounted disks or LiveUSB boot environments.

**Current Version:** v1.6.1-unstoppable-receipt

## Key Commands

### Running the Script

```bash
# Basic execution with custom output directory
./sequoia_forensic.sh --out /tmp/case

# Fast live triage (no imaging, quick mode)
./sequoia_forensic.sh --no-image-ok --fast --skip-logs --out ~/Desktop/case_fast

# Full acquisition with disk imaging (requires sudo)
sudo ./sequoia_forensic.sh --out /cases/case001

# View all available options
./sequoia_forensic.sh --help
```

### Testing and Development

```bash
# Run in debug mode
./sequoia_forensic.sh --debug --no-image-ok --out /tmp/test_run

# Test with verbose output
./sequoia_forensic.sh --verbose --no-image-ok --out /tmp/verbose_test
```

## Architecture

### Script Structure (sequoia_forensic.sh)

The script follows a strict **acquisition-first workflow**:

1. **Defaults & CLI Parsing** (lines 14-128): Command-line argument processing with sensible defaults
2. **Privilege & Debug Scaffolding** (lines 144-176): Root detection, sudo elevation helpers, debug traps
3. **Utilities** (lines 192-254): Helper functions for path resolution, reference file creation, timeout handling
4. **Capabilities Banner** (lines 259-396): Runtime environment detection and capability reporting
5. **Chain of Custody** (lines 478-526): Metadata tracking with JSON output
6. **Acquisition Phase** (lines 531-582): Disk imaging with ddrescue/dd and SHA-256 hashing
7. **Collection Functions** (lines 587-893): Individual collectors for different artifact types
8. **Reporting** (lines 898-933): HTML report generation
9. **Packaging** (lines 938-987): ZIP creation, encryption, Discord webhook upload
10. **Orchestration** (lines 992-1057): Sequential step execution with progress tracking

### Key Design Patterns

**Error Handling Philosophy:**
- Uses `set -euo pipefail` globally but disables `-e` within individual collection steps
- Each collection function runs in a subshell with error traps cleared
- Non-fatal collectors: one failure never aborts the entire run
- Returns are always `0` to continue orchestration (see `suspicious_procs`, `collect_fsevents`)

**Acquisition-First Guard:**
- When `FORENSIC_MODE=true` (default), disk imaging must complete before analysis steps
- Can be bypassed with `--no-forensic` or `--no-image-ok` flags
- Enforced via `IMAGING_DONE` flag check in orchestration loop (line 1034)

**Performance Optimization:**
- `FAST_MODE` flag (--fast) reduces timeout windows and limits deep scans
- Conditional tool availability checks with capability reporting
- Timeout wrapper (`run_with_timeout`) prevents hangs on heavy operations like Unified Log extraction

**Privilege Escalation:**
- `run_elev()` helper (lines 177-187) attempts sudo only when needed
- Operations that fail due to permissions are logged to `permission_skips.txt` via `note_skip()`
- Interactive sudo prompt can be requested with `--ask-sudo`

### Collection Steps (Orchestration)

Steps execute in order via arrays `STEPS[]` and `FUNCS[]` (lines 992-1027):

1. **Disk imaging + hashing** → `image_and_hash()`
2. **System snapshot** → `collect_system_snapshot()`
3. **Copy key system files** → `collect_key_files()`
4. **Login activity** → `collect_login_activity()`
5. **Unified logs** → `collect_unified_logs()` (can be bypassed with `--skip-logs` or runtime prompt)
6. **FSEvents** → `collect_fsevents()` (handles nullglob state, multiple volumes)
7. **Audit logs** → `collect_audit_logs()`
8. **USB & mount info** → `collect_usb_and_mounts()`
9. **Network state** → `collect_network_state()`
10. **Find recent files** → `find_recent_files()`
11. **Collect user metadata** → `collect_user_metadata()`
12. **Suspicious processes** → `suspicious_procs()` (detects unsigned, from /tmp, reverse shells)
13. **Cron & launchd inspection** → `cron_and_launchd_check()`
14. **Sudo activity** → `sudo_activity()`
15. **Build HTML report** → `build_html_report()`
16. **Package / Encrypt / Upload** → inline logic with `package_zip()`, `encrypt_artifact()`, `discord_upload()`

### Output Structure

All output goes to `$OUTDIR` (default: `./sequoia_forensic_<timestamp>`):

```
$OUTDIR/
├── collector.log              # Main execution log
├── run_status.txt             # Start/end timestamps, exit code
├── environment.txt/.json      # Runtime capabilities
├── chain_of_custody.json      # CoC metadata
├── report.html                # HTML5 report
├── image/                     # Disk images, hashes, progress logs
├── fsevents/                  # Per-volume .fseventsd copies
├── audit/                     # Audit trail files + praudit decoded
├── suspicious/                # Process artifacts, unsigned binaries, SUID files
├── scheduled/                 # Cron, LaunchDaemons, user LaunchAgents
├── sudo/                      # Recent sudo activity
├── users/                     # Per-user metadata (plists)
└── permission_skips.txt       # List of operations skipped due to permissions
```

## Important Constraints

### Bash 3.2 Compatibility

macOS ships with Bash 3.2. The script avoids:
- Associative arrays (Bash 4+)
- `mapfile`/`readarray` (Bash 4+)
- `**` globstar (requires `shopt -s globstar`)

Uses instead:
- Process substitution with `while read -r -d '' ... < <(find ... -print0)`
- Classic indexed arrays
- Portable `jot` or `seq` for loops

### Permission Handling

- Script attempts operations without elevation first
- Falls back to `run_elev()` for privileged operations
- Full Disk Access (FDA) may be required for user Library folders, Messages, Mail
- SIP restricts access to /System and protected files even with root
- Interactive device picker requires TTY (`-t 0` check)

### Timeouts and Safety Rails

- Unified Log plaintext extraction: 120s timeout (60s in FAST mode), limited to 24h window
- `run_with_timeout()` uses Python if available, falls back to backgrounded shell with sleep killer
- FSEvents collection uses tar-copy with fallback to per-file cp
- `find` operations prune `/dev`, `/proc`, `/sys`, `/Volumes`

## Development Guidelines

### Adding a New Collection Step

1. Write the collector function following the pattern:
   ```bash
   new_collector() {
     set +e                    # Disable exit-on-error
     mkdir -p "$OUTDIR/new_artifact"
     # ... collection logic ...
     set -e
     return 0                  # Always return success
   }
   ```

2. Add step to `STEPS[]` array (line 992)
3. Add function name to `FUNCS[]` array (line 1010)
4. Test with `--debug --verbose --no-image-ok`

### Modifying Report Generation

HTML report is built in `build_html_report()` (lines 898-933):
- Uses inline CSS with dark theme
- Links to artifacts in `$OUTDIR`
- Includes environment card via `env_card_html()`

### Encryption Support

Three methods supported via `encrypt_artifact()`:
- **age** (preferred): Uses public key recipient file
- **gpg**: Uses recipient ID
- **openssl**: Uses PEM public key, creates `.enc`, `.key`, `.iv` files

Auto-detection via `--encrypt-method auto` checks for tool availability.

## Common Scenarios

### Offline Analysis from Mounted Disk

```bash
# Mount the target disk at /Volumes/Evidence
./sequoia_forensic.sh --root /Volumes/Evidence --no-image-ok --out ~/cases/offline_case
```

### Remote Collection with Encryption

```bash
# Generate age keypair first: age-keygen -o key.txt
./sequoia_forensic.sh --no-image-ok --fast \
  --encrypt age:key.pub \
  --webhook https://discord.com/api/webhooks/... \
  --out ~/Desktop/remote_case
```

### Debugging Permission Issues

```bash
# Run with debug mode and check outputs
./sequoia_forensic.sh --debug --verbose --no-image-ok --out /tmp/debug_run

# Review what was skipped
cat /tmp/debug_run/permission_skips.txt
cat /tmp/debug_run/debug.trace
```

## Dependencies

### Required
- Bash 3.2+ (macOS default)
- Standard POSIX utilities: `find`, `ls`, `cp`, `tar`, `zip`, `netstat`, `ps`, `awk`, `sed`

### Optional (capability-detected)
- **Imaging:** `ddrescue` (preferred), `pv` (progress), `dd` (fallback)
- **Logs:** `log` (Unified Log), `praudit` (audit decoding)
- **Network:** `lsof`, `pfctl`
- **Profiling:** `system_profiler`
- **Security:** `osquery`, `rkhunter`, `chkrootkit`
- **Encryption:** `age`, `gpg`, `openssl`
- **Hashing:** `shasum` or `sha256sum`

Check available tools in the "Capabilities Banner" at runtime or in `environment.json`.
