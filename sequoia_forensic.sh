#!/usr/bin/env bash
# sequoia_forensic.sh
# macOS Sequoia (15) forensic collector & imager — acquisition-first, CoC, env card, encryption, Discord
# Optimized for correctness + lower runtime/resource cost. Bash 3.2 compatible.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.6.1-unstoppable-receipt"

# -----------------------
# Defaults & CLI
# -----------------------
ROOT="/"
OUTDIR="./sequoia_forensic_$(date -u +%Y%m%dT%H%M%SZ)"
SINCE="7d"
IMAGE_DEV=""
DISCORD_WEBHOOK=""
INCLUDE_SYSTEM=false
VERBOSE=false
FAST_MODE=false            # NEW: trims expensive steps
# Unified logs bypass controls
ASK_BYPASS_LOGS=false   # prompt y/N at runtime if interactive
SKIP_LOGS=false         # non-interactive full skip (CLI)
RUN_STATUS="$OUTDIR/run_status.txt"
echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RUN_STATUS"


# Acquisition guard
FORENSIC_MODE=true
NO_IMAGE_OK=false
RAW_DEVICE_SPEEDUP=true
READONLY_HINTS=true

# CoC metadata
CASE_ID=""
OPERATOR=""
LOCATION=""
EVIDENCE_DESC=""
NOTES=""

# Encryption
ENCRYPT_PUBKEY=""
ENCRYPT_METHOD="auto"
ENCRYPTED_FILE=""

# Debug / auth helpers
DEBUG_MODE=false
ASK_SUDO=false

# Unified log plaintext safety rails (bounded quick-view; full archive is kept)
LOG_PLAIN_TIMEOUT=120      # seconds (reduced)
LOG_PLAIN_MAX_WINDOW="24h" # cap plaintext window tighter for speed

usage() {
  cat <<EOF
sequoia_forensic.sh - acquisition-first macOS forensic collector & imager

General:
  --root <path>              Target root (default /)
  --out <path>               Output dir
  --since <ISO|REL>          "2025-09-01T00:00:00" | "72h" | "7d" (default 7d)
  --image <blockdev>         Image device (/dev/disk2); picker used if omitted (interactive TTY)
  --include-system           Include /System in modified-file list (slower)
  --verbose                  Verbose logging
  --fast                     Trim expensive checks for speed (see Notes)

Chain of Custody:
  --case-id <id>             Case ID
  --operator <name>          Operator name/role
  --location <place>         Collection location
  --evidence-desc <text>     Evidence description
  --notes <text>             Notes

Encryption:
  --encrypt-pubkey <file>    Public key (age recipient file, GPG recipient ID, or PEM for openssl)
  --encrypt-method <m>       auto | age | gpg | openssl  (default: auto)

Discord:
  --discord <webhook_url>    Upload (encrypted) zip to Discord webhook

Advanced:
  --no-forensic              Disable acquisition-first guard
  --no-image-ok              Permit analysis without imaging
  --no-raw                   Use /dev/disk* (not rdisk*)
  --no-readonly-hints        Skip unmount attempts before imaging
  --debug                    Enable xtrace + ERR/EXIT traps
  --ask-sudo                 Try sudo -v upfront (non-root)
  --help
EOF
  exit 1
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2;;
    --out) OUTDIR="$2"; shift 2;;
    --since) SINCE="$2"; shift 2;;
    --image) IMAGE_DEV="$2"; shift 2;;
    --discord) DISCORD_WEBHOOK="$2"; shift 2;;
    --include-system) INCLUDE_SYSTEM=true; shift;;
    --verbose) VERBOSE=true; shift;;
    --fast) FAST_MODE=true; shift;;
    --ask-skip-logs) ASK_BYPASS_LOGS=true; shift;;
    --skip-logs)     SKIP_LOGS=true; shift;;

    --no-forensic) FORENSIC_MODE=false; shift;;
    --no-image-ok) NO_IMAGE_OK=true; shift;;
    --no-raw) RAW_DEVICE_SPEEDUP=false; shift;;
    --no-readonly-hints) READONLY_HINTS=false; shift;;

    --case-id) CASE_ID="$2"; shift 2;;
    --operator) OPERATOR="$2"; shift 2;;
    --location) LOCATION="$2"; shift 2;;
    --evidence-desc) EVIDENCE_DESC="$2"; shift 2;;
    --notes) NOTES="$2"; shift 2;;

    --encrypt-pubkey) ENCRYPT_PUBKEY="$2"; shift 2;;
    --encrypt-method) ENCRYPT_METHOD="$2"; shift 2;;

    --debug) DEBUG_MODE=true; shift;;
    --ask-sudo) ASK_SUDO=true; shift;;

    --help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

mkdir -p "$OUTDIR"
LOG="$OUTDIR/collector.log"
exec > >(tee -a "$LOG") 2>&1

echov(){ [ "$VERBOSE" = true ] && echo "$*"; }

echo "[start] Output -> $OUTDIR"
echo "[start] Target root -> $ROOT"
echo "[start] Time window -> $SINCE"
echo "[start] Mode -> forensic=$FORENSIC_MODE fast=$FAST_MODE include_system=$INCLUDE_SYSTEM"

# -----------------------
# Privilege + Debug scaffolding
# -----------------------
IS_ROOT=false
[ "$(id -u)" -eq 0 ] && IS_ROOT=true

if $ASK_SUDO && ! $IS_ROOT; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[auth] sudo -v …"
    sudo -v || echo "[auth] sudo not permitted; continuing without elevation"
  fi
fi

DEBUG_LOG="$OUTDIR/debug.trace"
if $DEBUG_MODE; then
  export PS4='+${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}: '
  set -o xtrace
fi
# --- Debug traps (quiet on success) ---
debug_trap() {
  local e=$?
  # Only print ERR frames when DEBUG_MODE is on
  if [ "${DEBUG_MODE:-false}" = true ]; then
    echo "[DEBUG][ERR] ${BASH_SOURCE[1]-main}:${BASH_LINENO[0]-0}: '${BASH_COMMAND}' exit=$e" | tee -a "$DEBUG_LOG" >&2
  fi
}
# Print EXIT line only on non-zero OR when DEBUG_MODE=true
exit_trap() {
  local rc=$?
  if [ "$rc" -ne 0 ] || [ "${DEBUG_MODE:-false}" = true ]; then
    echo "[DEBUG][EXIT] status=$rc at $(date -u +%FT%TZ)" | tee -a "$DEBUG_LOG"
  fi
}
trap debug_trap ERR
trap exit_trap EXIT

run_elev() {
  # usage: run_elev <desc> <cmd...>
  local desc="$1"; shift
  if $IS_ROOT; then
    "$@" && return 0
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@" && return 0
  fi
  echo "[perm][skip] $desc requires elevated privileges." >&2
  return 1
}

# -----------------------
# Utils
# -----------------------
rpath() {
  local p="$1"
  if [ "$ROOT" = "/" ]; then echo "$p"; else [[ "$p" == /* ]] && p="${p:1}"; echo "${ROOT}/${p}"; fi
}

create_reffile() {
  local since="$1" reffile="$OUTDIR/.since_ref"
  if [[ "$since" =~ ^[0-9]+[dhm]$ ]]; then
    local num=${since::-1} unit=${since: -1}
    local rel; case "$unit" in d) rel="-${num}d";; h) rel="-${num}h";; m) rel="-${num}M";; *) rel="-${num}h";; esac
    if date -v"${rel}" >/dev/null 2>&1; then touch -t "$(date -u -v"${rel}" +%Y%m%d%H%M.%S)" "$reffile"; else touch "$reffile"; fi
  else
    if date -j -f "%Y-%m-%dT%H:%M:%S" "$since" >/dev/null 2>&1; then
      touch -t "$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$since" +%Y%m%d%H%M.%S)" "$reffile"
    elif date -j -f "%Y-%m-%d" "$since" >/dev/null 2>&1; then
      touch -t "$(date -u -j -f "%Y-%m-%d" "$since" +%Y%m%d%H%M.%S)" "$reffile"
    else
      echo "[warn] Could not parse --since '$since'; defaulting to 7d"
      touch -t "$(date -u -v-7d +%Y%m%d%H%M.%S)" "$reffile"
    fi
  fi
  echo "$reffile"
}
REF_FILE=$(create_reffile "$SINCE")

pick_blockdev(){ $RAW_DEVICE_SPEEDUP && echo "${1/disk/rdisk}" || echo "$1"; }
readonly_prepare_target(){ $READONLY_HINTS && run_elev "unmount device $1" diskutil unmountDisk "$1" >/dev/null 2>&1 || true; }

# Skips log
SKIPS_FILE="$OUTDIR/permission_skips.txt"
note_skip(){ echo "$1" >> "$SKIPS_FILE"; }

# Run a command with hard timeout (Python if available; POSIX fallback)
run_with_timeout() {
  local seconds="$1"; shift
  if command -v /usr/bin/python3 >/dev/null 2>&1; then
    /usr/bin/python3 - "$seconds" "$@" <<'PY'
import os, sys, subprocess, time
secs = int(sys.argv[1]); cmd = sys.argv[2:]
p = subprocess.Popen(cmd)
t0 = time.time()
while True:
  ret = p.poll()
  if ret is not None:
    sys.exit(ret)
  if time.time() - t0 > secs:
    try:
      p.terminate(); time.sleep(0.8)
      if p.poll() is None: p.kill()
    except Exception: pass
    sys.exit(124)
  time.sleep(0.15)
PY
    return $?
  else
    "$@" & local pid=$!
    ( sleep "$seconds"; kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null ) &
    local waiter=$!
    wait "$pid" 2>/dev/null; local rc=$?
    kill -0 "$waiter" 2>/dev/null && kill "$waiter" 2>/dev/null || true
    [ "$rc" -eq 137 ] && return 124 || return "$rc"
  fi
}

# -----------------------
# Capabilities Banner + Environment artifacts
# -----------------------
capabilities_banner() {
  echo
  echo "==================== CAPABILITIES ===================="
  local tty="no"; [ -t 0 ] && tty="yes"
  local sip="unknown"
  command -v csrutil >/dev/null 2>&1 && sip="$(csrutil status 2>/dev/null | tr -d '\r' | tr '\n' ' ')"

  # Presence toggles
  local sudo_avail="no"; command -v sudo >/dev/null 2>&1 && sudo_avail="yes"
  local ddrescue_avail="no"; command -v ddrescue >/dev/null 2>&1 && ddrescue_avail="yes"
  local pv_avail="no"; command -v pv >/dev/null 2>&1 && pv_avail="yes"
  local age_avail="no"; command -v age >/dev/null 2>&1 && age_avail="yes"
  local gpg_avail="no"; command -v gpg >/dev/null 2>&1 && gpg_avail="yes"
  local openssl_avail="no"; command -v openssl >/dev/null 2>&1 && openssl_avail="yes"
  local praudit_avail="no"; command -v praudit >/dev/null 2>&1 && praudit_avail="yes"
  local osquery_avail="no"; command -v osqueryi >/dev/null 2>&1 && osquery_avail="yes"
  local rkhunter_avail="no"; command -v rkhunter >/dev/null 2>&1 && rkhunter_avail="yes"
  local chkrootkit_avail="no"; command -v chkrootkit >/dev/null 2>&1 && chkrootkit_avail="yes"
  local lsof_avail="no"; command -v lsof >/dev/null 2>&1 && lsof_avail="yes"
  local pfctl_avail="no"; command -v pfctl >/dev/null 2>&1 && pfctl_avail="yes"
  local log_avail="no"; command -v log >/dev/null 2>&1 && log_avail="yes"
  local sysprof_avail="no"; command -v system_profiler >/dev/null 2>&1 && sysprof_avail="yes"

  # FDA heuristic
  local fda="unknown"
  if [ -n "${HOME:-}" ]; then
    if ls -d "$HOME/Library/Messages" >/dev/null 2>&1 || ls -d "$HOME/Library/Mail" >/dev/null 2>&1; then
      fda="likely yes"
    else
      fda="likely no"
    fi
  fi

  printf "%-28s : %s\n" "Script version" "$SCRIPT_VERSION"
  printf "%-28s : %s\n" "Running as root" "$IS_ROOT"
  printf "%-28s : %s\n" "sudo available" "$sudo_avail"
  printf "%-28s : %s\n" "TTY (interactive)" "$tty"
  printf "%-28s : %s\n" "SIP" "$sip"
  printf "%-28s : %s\n" "Full Disk Access (heuristic)" "$fda"

  echo "---- Imaging & collectors ----"
  printf "%-28s : %s\n" "ddrescue" "$ddrescue_avail"
  printf "%-28s : %s\n" "pv" "$pv_avail"
  printf "%-28s : %s\n" "log" "$log_avail"
  printf "%-28s : %s\n" "system_profiler" "$sysprof_avail"
  printf "%-28s : %s\n" "praudit" "$praudit_avail"
  printf "%-28s : %s\n" "osquery" "$osquery_avail"
  printf "%-28s : %s\n" "rkhunter" "$rkhunter_avail"
  printf "%-28s : %s\n" "chkrootkit" "$chkrootkit_avail"
  printf "%-28s : %s\n" "lsof" "$lsof_avail"
  printf "%-28s : %s\n" "pfctl" "$pfctl_avail"

  echo "---- Encryption ----"
  printf "%-28s : %s\n" "age" "$age_avail"
  printf "%-28s : %s\n" "gpg" "$gpg_avail"
  printf "%-28s : %s\n" "openssl" "$openssl_avail"

  echo "---- Flow ----"
  printf "%-28s : %s\n" "Acquisition-first guard" "$FORENSIC_MODE"
  printf "%-28s : %s\n" "FAST mode" "$FAST_MODE"
  [ -n "$IMAGE_DEV" ] && printf "%-28s : %s\n" "Imaging device" "$IMAGE_DEV" || printf "%-28s : %s\n" "Imaging device" "not set"
  echo "======================================================"
  echo

  # Environment artifacts
  local host os_ver kernel
  host="$(scutil --get ComputerName 2>/dev/null || hostname)"
  os_ver="$(sw_vers 2>/dev/null | tr '\n' ' ' || uname -a)"
  kernel="$(uname -a)"

  {
    echo "=== Environment Summary ==="
    echo "Generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Script Version : $SCRIPT_VERSION"
    echo "Host           : $host"
    echo "OS             : $os_ver"
    echo "Kernel         : $kernel"
    echo "SIP            : $sip"
    echo "User           : $(id -un) (uid=$(id -u))  root=$IS_ROOT  sudo=$sudo_avail"
    echo "TTY            : $tty"
    echo "Full Disk Access (heuristic): $fda"
    echo "Acquisition-first guard     : $FORENSIC_MODE"
    echo "FAST mode                   : $FAST_MODE"
    echo "Imaging device              : ${IMAGE_DEV:-<none>}"
    echo "Raw device speedup          : $RAW_DEVICE_SPEEDUP"
    echo "Readonly unmount attempt    : $READONLY_HINTS"
  } > "$OUTDIR/environment.txt"

  export OUTDIR IMAGE_DEV FORENSIC_MODE IS_ROOT
  export CAP_HOST="$host" CAP_OS_VER="$os_ver" CAP_KERNEL="$kernel" CAP_SIP="$sip"
  export CAP_TTY="$tty" CAP_FDA="$fda" CAP_SCRIPT_VERSION="$SCRIPT_VERSION" CAP_FAST="$FAST_MODE"
  for k in ddrescue pv log system_profiler praudit osqueryi rkhunter chkrootkit lsof pfctl age gpg openssl; do
    v="no"; command -v "$k" >/dev/null 2>&1 && v="yes"
    eval "export CAP_$(echo "$k" | tr a-z A-Z | tr '.' '_')=\"$v\""
  done

  if command -v /usr/bin/python3 >/dev/null 2>&1; then
    /usr/bin/python3 - <<'PY' || true
import json, os, datetime
tf=lambda x: str(x).lower() in ("1","true","yes","on")
cap = {
  "generated_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
  "script_version": os.environ.get("CAP_SCRIPT_VERSION",""),
  "host": os.environ.get("CAP_HOST",""),
  "os": os.environ.get("CAP_OS_VER",""),
  "kernel": os.environ.get("CAP_KERNEL",""),
  "sip_status": os.environ.get("CAP_SIP",""),
  "is_root": tf(os.environ.get("IS_ROOT","false")),
  "tty": os.environ.get("CAP_TTY","no"),
  "full_disk_access_heuristic": os.environ.get("CAP_FDA","unknown"),
  "fast_mode": tf(os.environ.get("CAP_FAST","false")),
  "collectors": {
    "ddrescue": os.environ.get("CAP_DDRESCUE","no"),
    "pv": os.environ.get("CAP_PV","no"),
    "log": os.environ.get("CAP_LOG","no"),
    "system_profiler": os.environ.get("CAP_SYSTEM_PROFILER","no"),
    "praudit": os.environ.get("CAP_PRAUDITI","no") or os.environ.get("CAP_PRAUDIT","no"),
    "osquery": os.environ.get("CAP_OSQUERYI","no"),
    "rkhunter": os.environ.get("CAP_RKHUNTER","no"),
    "chkrootkit": os.environ.get("CAP_CHKROOTKIT","no"),
    "lsof": os.environ.get("CAP_LSOF","no"),
    "pfctl": os.environ.get("CAP_PFCTL","no")
  },
  "encryption": {
    "age": os.environ.get("CAP_AGE","no"),
    "gpg": os.environ.get("CAP_GPG","no"),
    "openssl": os.environ.get("CAP_OPENSSL","no")
  },
  "flow": {
    "acquisition_first": tf(os.environ.get("FORENSIC_MODE","true")),
    "imaging_device": os.environ.get("IMAGE_DEV","")
  }
}
outdir=os.environ.get("OUTDIR",".")
open(os.path.join(outdir,"environment.json"),"w").write(json.dumps(cap,indent=2))
PY
  fi
}

capabilities_banner

# -----------------------
# Environment card (HTML)
# -----------------------
env_card_html() {
  echo '<div class="card"><h2>Environment</h2>'
  echo '<p class="muted">Runtime context & tools available on this box.</p>'
  echo '<ul>'
  echo '  <li><strong>Script version:</strong> '"$SCRIPT_VERSION"'</li>'
  echo '  <li><strong>Acquisition-first guard:</strong> '"$FORENSIC_MODE"'</li>'
  echo '  <li><strong>FAST mode:</strong> '"$FAST_MODE"'</li>'
  echo '  <li><strong>Imaging device:</strong> '"${IMAGE_DEV:-&lt;none&gt;}"'</li>'
  echo '  <li><strong>Raw device mode:</strong> '"$RAW_DEVICE_SPEEDUP"'</li>'
  echo '  <li><strong>Readonly unmount attempt:</strong> '"$READONLY_HINTS"'</li>'
  echo '</ul>'
  echo '<p>Details: <a href="./environment.txt">environment.txt</a> &middot; <a href="./environment.json">environment.json</a></p>'
  echo '</div>'
}

# -----------------------
# Interactive device picker
# -----------------------
pick_device_interactive() {
  echo; echo "No --image specified. Available disks:"
  diskutil list
  echo
  printf "Enter device identifier (e.g., disk0), or Enter to skip: "
  read choice
  if [ -n "$choice" ]; then IMAGE_DEV="/dev/${choice}"; echo "[picker] Selected: $IMAGE_DEV"; else echo "[picker] Skipping imaging."; fi
}

# -----------------------
# Progress bar / ETA
# -----------------------
TOTAL_ELAPSED=0
RUN_COUNT=0
progress_print() {
  local cur="$1" total="$2" elapsed="$3"
  local pct=$(( cur * 100 / total ))
  local barlen=34; local filled=$(( pct * barlen / 100 )); local empty=$(( barlen - filled ))
  local bar="$(printf '%0.s#' $(jot - 1 $filled 2>/dev/null || seq 1 $filled))$(printf '%0.s-' $(jot - 1 $empty 2>/dev/null || seq 1 $empty))"
  local avg=0; [ "$cur" -gt 0 ] && avg=$(( elapsed / cur ))
  local rem=$(( total - cur )); local eta=$(( avg * rem ))
  printf "\r[%s] %3d%%  step %d/%d  ETA %02d:%02d" "$bar" "$pct" "$cur" "$total" "$((eta/60))" "$((eta%60))"
}
run_step() {
  local label="$1" func="$2"
  RUN_COUNT=$((RUN_COUNT+1))
  echo; echo "----------------------------------------------------------------"
  echo "STEP $RUN_COUNT: $label"

  local start end dur rc
  start=$(date +%s)

  # Run the step in a subshell with -e disabled and ERR trap cleared.
  # This guarantees the main script keeps going even if the step returns non-zero.
  (
    set +e
    trap - ERR
    "$func"
  )
  rc=$?

  end=$(date +%s)
  dur=$((end-start))
  TOTAL_ELAPSED=$((TOTAL_ELAPSED+dur))

  progress_print "$RUN_COUNT" "${#STEPS[@]}" "$TOTAL_ELAPSED"; echo

  if [ $rc -ne 0 ]; then
    echo "WARN: $label completed with non-zero status ($rc) after ${dur}s — continuing."
  else
    echo "DONE: $label (${dur}s)"
  fi
}

# -----------------------
# Chain of Custody
# -----------------------
CoC_JSON="$OUTDIR/chain_of_custody.json"
write_coc() {
  local now_utc; now_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  cat > "$CoC_JSON" <<JSON
{
  "case_id": "$(printf %s "$CASE_ID")",
  "operator": "$(printf %s "$OPERATOR")",
  "location": "$(printf %s "$LOCATION")",
  "evidence_description": "$(printf %s "$EVIDENCE_DESC")",
  "notes": "$(printf %s "$NOTES")",
  "start_utc": "$now_utc",
  "acquisition": {
    "device": "$(printf %s "${IMAGE_DEV:-}")",
    "raw_device_mode": $RAW_DEVICE_SPEEDUP,
    "readonly_attempt": $READONLY_HINTS
  },
  "hashes": { "image_sha256": "" },
  "transfers": []
}
JSON
}
coc_update_hash() {
  local sha="$1"
  if command -v /usr/bin/python3 >/dev/null 2>&1; then
    /usr/bin/python3 - "$sha" "$CoC_JSON" <<'PY' || true
import json,sys
sha=sys.argv[1]; p=sys.argv[2]
j=json.load(open(p))
j['hashes']['image_sha256']=sha
open(p,'w').write(json.dumps(j,indent=2))
PY
  else
    sed -i '' "s/\"image_sha256\": \"\"/\"image_sha256\": \"${sha//\//\\/}\"/g" "$CoC_JSON" 2>/dev/null || true
  fi
}
coc_add_transfer() {
  local who="$1" why="$2" when; when=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if command -v /usr/bin/python3 >/dev/null 2>&1; then
    /usr/bin/python3 - "$CoC_JSON" "$when" "$who" "$why" <<'PY' || true
import json,sys
p,when,who,why=sys.argv[1:5]
j=json.load(open(p))
j.setdefault('transfers',[]).append({"utc":when,"by":who,"purpose":why})
open(p,'w').write(json.dumps(j,indent=2))
PY
  else
    echo "$when by=$who purpose=$why" >> "$OUTDIR/chain_of_custody.transfers.txt"
  fi
}

# -----------------------
# Acquisition (Step 1)
# -----------------------
IMAGING_DONE=false
IMG="" HASHFILE=""

image_and_hash() {
  write_coc
  if [ -z "${IMAGE_DEV:-}" ]; then [ -t 0 ] && pick_device_interactive; fi
  if [ -z "${IMAGE_DEV:-}" ]; then
    echo "[acquire] No --image device selected."
    if $FORENSIC_MODE && ! $NO_IMAGE_OK; then
      echo "[guard] Forensic mode requires an image or --no-image-ok."
      exit 2
    fi
    return 0
  fi

  local DEV_RAW; DEV_RAW="$(pick_blockdev "$IMAGE_DEV")"
  echo "[acquire] Preparing $DEV_RAW for imaging (best-effort RO)…"
  readonly_prepare_target "$IMAGE_DEV"

  mkdir -p "$OUTDIR/image"
  IMG="$OUTDIR/image/$(basename "$IMAGE_DEV").img"
  HASHFILE="$OUTDIR/image/$(basename "$IMAGE_DEV").sha256"
  local MAP="$OUTDIR/image/$(basename "$IMAGE_DEV").map"

  echo "[acquire] Imaging $DEV_RAW -> $IMG"
  if command -v ddrescue >/dev/null 2>&1; then
    run_elev "ddrescue imaging" ddrescue -f -n "$DEV_RAW" "$IMG" "$MAP" 2>&1 | tee "$OUTDIR/image/ddrescue_progress.txt" || true
    run_elev "ddrescue retry"   ddrescue -f -r2 "$DEV_RAW" "$IMG" "$MAP" 2>&1 | tee -a "$OUTDIR/image/ddrescue_progress.txt" || true
  else
    if command -v pv >/dev/null 2>&1; then
      run_elev "pv|dd imaging" sh -c "pv '$DEV_RAW' | dd of='$IMG' bs=1m" 2> "$OUTDIR/image/dd_progress.txt" || true
    else
      run_elev "dd imaging" dd if="$DEV_RAW" of="$IMG" bs=1m 2> "$OUTDIR/image/dd_progress.txt" || true
    fi
  fi

  echo "[acquire] Hashing (SHA-256)…"
  local sha=""
  if command -v shasum >/dev/null 2>&1; then sha=$(shasum -a 256 "$IMG" | awk '{print $1}')
  elif command -v sha256sum >/dev/null 2>&1; then sha=$(sha256sum "$IMG" | awk '{print $1}')
  fi
  [ -n "$sha" ] && echo "$sha  $IMG" > "$HASHFILE" && coc_update_hash "$sha"

  if [ -s "$IMG" ]; then
    IMAGING_DONE=true
    echo "[acquire] Image: $IMG"
    echo "[acquire] Hash : $HASHFILE"
  else
    echo "[warn] Imaging produced empty file; continuing only if --no-image-ok."
    $FORENSIC_MODE && ! $NO_IMAGE_OK && exit 3 || true
  fi
}

# -----------------------
# Collection + Triage (optimized)
# -----------------------
collect_system_snapshot() {
  {
    uname -a
    sw_vers 2>/dev/null || true
    date -u
    uptime
    echo "diskutil list:"; diskutil list
    echo "df -h:"; df -h
  } > "$OUTDIR/system_snapshot.txt"
}

collect_key_files() {
  mkdir -p "$OUTDIR/keyfiles"
  cp -a "$(rpath /etc/hosts)" "$OUTDIR/keyfiles/" 2>/dev/null || true
  cp -a "$(rpath /etc/shells)" "$OUTDIR/keyfiles/" 2>/dev/null || true
  cp -a "$(rpath /etc/sudoers)" "$OUTDIR/keyfiles/" 2>/dev/null || true
  cp -a "$(rpath /var/db/dhcpd_leases)" "$OUTDIR/keyfiles/" 2>/dev/null || true
}

collect_login_activity() {
  {
    echo "last -n 150:"; last -n 150 2>/dev/null || true
    echo; echo "who:"; who || true
    echo; echo "last reboot:"; last reboot -n 12 2>/dev/null || true
  } > "$OUTDIR/login_history.txt"
}

should_skip_logs() {
  # Non-interactive override
  [ "$SKIP_LOGS" = true ] && return 0

  # Prompt only if interactive and ask flag is enabled
  if [ "$ASK_BYPASS_LOGS" = true ] && [ -t 0 ]; then
    printf "Unified logs can be heavy. Bypass STEP 5 entirely? [y/N]: "
    read ans
    case "$ans" in
      y|Y|yes|YES) return 0;;
    esac
  fi

  return 1
}

collect_unified_logs() {
  # Allow bypass via prompt or CLI
  if should_skip_logs; then
    echo "[logs] STEP 5 bypassed by user choice."
    return 0
  fi

  local plain_since="$SINCE"
  # cap plaintext window; more aggressive in FAST mode
  if [[ "$plain_since" =~ ^([0-9]+)d$ ]]; then
    local days="${BASH_REMATCH[1]}"
    local cap=$([ "$FAST_MODE" = true ] && echo "12h" || echo "$LOG_PLAIN_MAX_WINDOW")
    [ "$days" -gt 1 ] && plain_since="$cap"
  fi
  local to=$([ "$FAST_MODE" = true ] && echo 60 || echo "$LOG_PLAIN_TIMEOUT")

  if [ "$ROOT" = "/" ] && command -v log >/dev/null 2>&1; then
    echo "[logs] collecting archive (offline-ready)…"
    run_elev "unified log collect" log collect --output "$OUTDIR/system_logs.logarchive" --last "$SINCE" || note_skip "log collect (archive)"

    echo "[logs] plaintext quick-view ($plain_since, ${to}s timeout)…"
    local PLAIN="$OUTDIR/unified_log_raw.txt"; local ERRZ="$OUTDIR/unified_log_raw.stderr"
    if run_with_timeout "$to" log show --style syslog --last "$plain_since" --info --debug --no-pager > "$PLAIN" 2> "$ERRZ"; then
      : # ok
    else
      local rc=$?
      echo "[logs][warn] plaintext timed out (rc=$rc). Use the .logarchive for full analysis." | tee -a "$PLAIN"
      echo "[logs][warn] stderr -> $ERRZ"
    fi
  else
    mkdir -p "$OUTDIR/collected_logs"
    cp -a "$(rpath /var/log/)" "$OUTDIR/collected_logs/" 2>/dev/null || true
    find "$(rpath /private/var)" -type f -name "*.logarchive" -maxdepth 4 -exec cp {} "$OUTDIR/collected_logs/" \; 2>/dev/null || true
  fi
}

collect_fsevents() {
  echo "[fsevents] begin"
  mkdir -p "$OUTDIR/fsevents"

  # Remember incoming -e state; we’ll relax it inside this step
  set +e

  # Track whether nullglob was set beforehand
  local had_ng=1
  shopt -q nullglob && had_ng=0 || { shopt -s nullglob; had_ng=1; }

  # Build volume list (respect --root)
  local vols=()
  if [ "$ROOT" = "/" ]; then
    vols+=( "/" )
    for v in /Volumes/*; do [ -e "$v" ] && vols+=( "$v" ); done
  else
    vols+=( "$ROOT" )
    for v in "$ROOT/Volumes"/*; do [ -e "$v" ] && vols+=( "$v" ); done
  fi

  for v in "${vols[@]}"; do
    # Normalize visual for log line (//.fseventsd looks scary but is fine)
    local src="$v/.fseventsd"
    local dest="$OUTDIR/fsevents/$(basename "$v")"
    echo "[fsevents] checking: $src"

    if [ ! -d "$src" ]; then
      echo "[fsevents] not found or not a dir: $src"
      continue
    fi

    mkdir -p "$dest"

    # Fast path: try tar copy; if it fails (permissions), fall back to per-file cp
    if ( cd "$src" 2>/dev/null && tar -cf - . 2>/dev/null | tar -xf - -C "$dest" 2>/dev/null ); then
      echo "[fsevents] tar-copied events for $v"
      continue
    fi

    # Per-file fallback; IMPORTANT: ensure the process substitution never propagates a failure
    # by forcing success with a trailing '|| true' inside a subshell.
    local copied=0
    while IFS= read -r -d '' file; do
      cp -a "$file" "$dest/" 2>/dev/null && { copied=1; continue; }
      run_elev "copy FSEvents from $src" cp -a "$file" "$dest/" && { copied=1; continue; }
      echo "[fsevents][warn] could not copy: $file"
      note_skip "FSEvents: $file"
    done < <( (find "$src" -maxdepth 1 -type f -print0 2>/dev/null || true) )

    [ "$copied" -eq 0 ] && echo "[fsevents] readable files not found in $src"
  done

  # Restore nullglob state and -e
  [ $had_ng -eq 1 ] && shopt -u nullglob || true
  set -e

  echo "[fsevents] end"
  return 0
}

collect_audit_logs() {
  mkdir -p "$OUTDIR/audit"; local aud; aud=$(rpath /var/audit)
  if [ -d "$aud" ]; then
    # limit decode volume in FAST mode
    local decode_limit=$([ "$FAST_MODE" = true ] && echo 5 || echo 999999)
    local count=0
    while IFS= read -r -d '' f; do
      local bn; bn=$(basename "$f")
      cp -a "$f" "$OUTDIR/audit/" 2>/dev/null || run_elev "copy audit $bn" cp -a "$f" "$OUTDIR/audit/" || { note_skip "audit: $bn"; continue; }
      if command -v praudit >/dev/null 2>&1; then
        if [ "$count" -lt "$decode_limit" ]; then
          ( praudit "$f" > "$OUTDIR/audit/$bn.txt" 2>/dev/null || true )
          count=$((count+1))
        fi
      fi
    done < <(find "$aud" -type f -print0 2>/dev/null)
  else
    echo "no /var/audit" > "$OUTDIR/audit/README.txt"
  fi
}

collect_usb_and_mounts() {
  cp -a "$(rpath /var/log/system.log)" "$OUTDIR/var_log_system.log" 2>/dev/null || true
  if [ "$ROOT" = "/" ] && command -v system_profiler >/dev/null 2>&1; then
    system_profiler SPUSBDataType > "$OUTDIR/system_profiler_SPUSB.txt" 2>/dev/null || true
    system_profiler SPNVMeDataType > "$OUTDIR/system_profiler_SPNVMe.txt" 2>/dev/null || true
  fi
}

collect_network_state() {
  netstat -an > "$OUTDIR/netstat_all.txt" 2>/dev/null || true
  command -v pfctl >/dev/null 2>&1 && pfctl -s state > "$OUTDIR/pf_state.txt" 2>/dev/null || true
  # lsof can be heavy; restrict in FAST mode
  if command -v lsof >/dev/null 2>&1; then
    if [ "$FAST_MODE" = true ]; then
      lsof -nP -iTCP -sTCP:LISTEN > "$OUTDIR/lsof_net.txt" 2>/dev/null || true
    else
      lsof -nP -i > "$OUTDIR/lsof_net.txt" 2>/dev/null || true
    fi
  fi
}

find_recent_files() {
  echo "Enumerating files modified since reference (bounded)…"
  local out="$OUTDIR/find_modified.txt"
  # prune common heavy trees; add -xdev to avoid crossing devices (FAST)
  if [ "$FAST_MODE" = true ]; then
    find "${ROOT}" -xdev \
      -path "${ROOT}/dev" -prune -o -path "${ROOT}/proc" -prune -o -path "${ROOT}/sys" -prune -o \
      -path "${ROOT}/Volumes" -prune -o \
      -type f -newer "$REF_FILE" -print 2>/dev/null > "$out" || true
  else
    find "${ROOT}" \
      -path "${ROOT}/dev" -prune -o -path "${ROOT}/proc" -prune -o -path "${ROOT}/sys" -prune -o \
      -type f -newer "$REF_FILE" -print 2>/dev/null > "$out" || true
  fi
  if [ "$INCLUDE_SYSTEM" = false ]; then sed -i '' '/\/System\//d' "$out" 2>/dev/null || true; fi
}

collect_user_metadata() {
  mkdir -p "$OUTDIR/users"; local users=()
  if [ "$ROOT" = "/" ]; then
    for u in /Users/*; do [ -d "$u" ] && users+=( "$u" ); done
  else
    for u in "$ROOT/Users"/*; do [ -d "$u" ] && users+=( "$u" ); done
  fi
  for u in "${users[@]}"; do
    local bn; bn=$(basename "$u"); mkdir -p "$OUTDIR/users/$bn"
    cp -a "$u/Library/Preferences/com.apple.recentitems.plist" "$OUTDIR/users/$bn/" 2>/dev/null || true
    cp -a "$u/Library/Preferences/com.apple.finder.plist" "$OUTDIR/users/$bn/" 2>/dev/null || true
    cp -a "$u/Library/Preferences/com.apple.loginitems.plist" "$OUTDIR/users/$bn/" 2>/dev/null || true
  done
}

suspicious_procs() {
  mkdir -p "$OUTDIR/suspicious"

  # Run the whole step with -e off; restore at the end.
  set +e

  ps aux > "$OUTDIR/suspicious/ps_aux.txt" 2>/dev/null || true

  # Net snapshots (best-effort)
  if command -v netstat >/dev/null 2>&1; then
    netstat -an > "$OUTDIR/suspicious/netstat.txt" 2>/dev/null || true
  fi
  if [ -f "$OUTDIR/lsof_net.txt" ]; then
    cp "$OUTDIR/lsof_net.txt" "$OUTDIR/suspicious/" 2>/dev/null || true
  fi

  # Processes launched from /tmp or /var/tmp
  awk '$11 ~ /^\/tmp/ || $11 ~ /^\/var\/tmp/ {print $0}' \
    "$OUTDIR/suspicious/ps_aux.txt" > "$OUTDIR/suspicious/from_tmp.txt" 2>/dev/null || true

  # Unsigned processes (bounded in FAST mode)
  : > "$OUTDIR/suspicious/unsigned_procs.txt"

  if [ "$FAST_MODE" = true ]; then
    # Only check PIDs that are listening or connected (smaller set)
    if [ -f "$OUTDIR/lsof_net.txt" ]; then
      awk 'NR>1 {print $2}' "$OUTDIR/lsof_net.txt" 2>/dev/null | sort -u | while read -r pid; do
        [ -z "$pid" ] && continue
        # Best-effort path detection
        procpath="$(lsof -p "$pid" -Fn 2>/dev/null | sed -n 's/^n//p' | head -n1)"
        [ -z "$procpath" ] && continue
        [ ! -f "$procpath" ] && continue
        # codesign non-zero is "unsigned" — record it, but never fail the step
        codesign -v "$procpath" >/dev/null 2>&1
        [ $? -ne 0 ] && echo "PID:$pid PATH:$procpath" >> "$OUTDIR/suspicious/unsigned_procs.txt"
      done
    fi
  else
    # Full sweep — still protected against transient failures
    while read -r line; do
      pid=$(echo "$line" | awk '{print $2}')
      [ -z "$pid" ] && continue
      procpath="$(lsof -p "$pid" -Fn 2>/dev/null | sed -n 's/^n//p' | head -n1)"
      if [ -z "$procpath" ]; then
        # fallback: first token of COMMAND column
        procpath=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf $i " "; print ""}' | awk '{print $1}')
      fi
      [ -z "$procpath" ] && continue
      [ ! -f "$procpath" ] && continue
      codesign -v "$procpath" >/dev/null 2>&1
      [ $? -ne 0 ] && echo "PID:$pid PATH:$procpath" >> "$OUTDIR/suspicious/unsigned_procs.txt"
    done < "$OUTDIR/suspicious/ps_aux.txt"
  fi

  # Names that hint at reverse shells/listeners — allow "no matches" without failing
  grep -Ei '(^|[ /])(nc|netcat|ncat|socat|meterpreter|python3? +-m +http\.server|bash +-i|sh +-i)( |$)' \
    "$OUTDIR/suspicious/ps_aux.txt" > "$OUTDIR/suspicious/sus_name_matches.txt" 2>/dev/null || true

  # suid/sgid sweep — errors to stderr, rc ignored
  find "${ROOT}" \( -perm -4000 -o -perm -2000 \) -type f -ls > "$OUTDIR/suspicious/suid_sgid_files.txt" 2>/dev/null || true

  set -e
  return 0
}

cron_and_launchd_check() {
  mkdir -p "$OUTDIR/scheduled"
  ls -la "$(rpath /etc/cron.d)" "$(rpath /etc/cron.daily)" "$(rpath /etc/cron.hourly)" \
          "$(rpath /etc/cron.weekly)" "$(rpath /var/at)" 2>/dev/null > "$OUTDIR/scheduled/cron_dirs.txt" || true
  echo "Per-user crontabs:" > "$OUTDIR/scheduled/crontabs.txt"
  local userlist=""
  [ -f "$(rpath /etc/passwd)" ] && userlist=$(cut -d: -f1 "$(rpath /etc/passwd)" || true)
  [ -z "$userlist" ] && userlist=$(dscl . -list /Users 2>/dev/null || true)
  for u in $userlist; do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /" >> "$OUTDIR/scheduled/crontabs.txt" || true; done
  find "$(rpath /Library/LaunchDaemons)" "$(rpath /Library/LaunchAgents)" \
       "$(rpath /System/Library/LaunchDaemons)" "$(rpath /System/Library/LaunchAgents)" \
       -name '*.plist' -maxdepth 2 -ls > "$OUTDIR/scheduled/launchd_plists.txt" 2>/dev/null || true
  find "$(rpath /Users)" -path "*/Library/LaunchAgents/*.plist" -ls > "$OUTDIR/scheduled/user_launch_agents.txt" 2>/dev/null || true

  # Dotfiles changed since ref
  find "$(rpath /Users)" -name ".*" -type f -newer "$REF_FILE" -ls > "$OUTDIR/scheduled/recent_dotfiles.txt" 2>/dev/null || true
}

sudo_activity() {
  mkdir -p "$OUTDIR/sudo"
  if command -v log >/dev/null 2>&1; then
    # smaller window in FAST mode
    local sw="$([ "$FAST_MODE" = true ] && echo "24h" || echo "$SINCE")"
    log show --style syslog --last "$sw" --predicate 'process == "sudo"' > "$OUTDIR/sudo/sudo_recent.txt" 2>/dev/null || true
  else
    echo "log(1) unavailable" > "$OUTDIR/sudo/README.txt"
  fi
}

# -----------------------
# HTML report
# -----------------------
build_html_report() {
  REPORT="$OUTDIR/report.html"
  local gen="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  {
  echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
  echo '<title>Sequoia Forensic Report</title><style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial;background:#0f1720;color:#e6eef8;padding:20px;line-height:1.45}.card{background:#0b1220;border:1px solid #172034;padding:14px;margin:12px 0;border-radius:10px}a{color:#7cc4ff}pre{white-space:pre-wrap;word-break:break-word;background:#071025;padding:10px;border-radius:8px;font-size:12px}h1,h2{color:#cfe9ff}.muted{color:#9fb4d0}.kv span{display:block;margin:.15rem 0}</style></head><body>'
  echo "<h1>Sequoia Forensic Report</h1><p class=\"muted\">Generated: ${gen}</p>"
  echo '<div class="card"><h2>Chain of Custody</h2><div class="kv">'
  echo "<span><strong>Case ID:</strong> ${CASE_ID}</span>"
  echo "<span><strong>Operator:</strong> ${OPERATOR}</span>"
  echo "<span><strong>Location:</strong> ${LOCATION}</span>"
  echo "<span><strong>Evidence:</strong> ${EVIDENCE_DESC}</span>"
  echo "<span><strong>Notes:</strong> ${NOTES}</span>"
  echo '</div><p>Full JSON: <a href="./chain_of_custody.json">chain_of_custody.json</a></p></div>'
  echo '<div class="card"><h2>Summary</h2><ul>'
  echo '  <li><a href="./system_snapshot.txt">System snapshot</a></li>'
  echo '  <li><a href="./login_history.txt">Login history</a></li>'
  echo '  <li><a href="./unified_log_raw.txt">Unified logs (raw subset)</a> — full archive: <code>system_logs.logarchive</code> (if present)</li>'
  echo '  <li><a href="./suspicious/unsigned_procs.txt">Unsigned processes</a></li>'
  echo '  <li><a href="./suspicious/suid_sgid_files.txt">SUID/SGID files</a></li>'
  echo '  <li><a href="./scheduled/launchd_plists.txt">LaunchDaemons/Agents</a></li>'
  echo '  <li><a href="./sudo/sudo_recent.txt">Recent sudo activity</a></li>'
  [ -f "$SKIPS_FILE" ] && echo '  <li><a href="./permission_skips.txt">Permission-related skips</a></li>'
  echo '</ul></div>'
  env_card_html
  echo '<div class="card"><h2>Quick Findings</h2>'
  echo '<h3>Unsigned processes</h3><pre>'
  [ -f "$OUTDIR/suspicious/unsigned_procs.txt" ] && sed -e '1,200!d' "$OUTDIR/suspicious/unsigned_procs.txt" || echo "None captured"
  echo '</pre><h3>Temp-launched processes</h3><pre>'
  [ -f "$OUTDIR/suspicious/from_tmp.txt" ] && sed -e '1,200!d' "$OUTDIR/suspicious/from_tmp.txt" || echo "None captured"
  echo '</pre></div>'
  echo '<div class="card"><h2>Notes</h2><p>This is a collection & heuristic summary. For deep analysis, open the <code>.logarchive</code> in Console or use <code>log show --archive</code>; parse <code>.fseventsd</code> with a suitable parser; and review <code>/var/audit</code> via <code>praudit</code>.</p>'
  echo '<p class="muted" style="opacity:.8;margin-top:12px">Brought to you by <strong>Scotty D.</strong> &amp; <strong>GPT</strong>.</p></div>'
  echo '</body></html>'
  } > "$REPORT"
}

# -----------------------
# Package / Encrypt / Discord
# -----------------------
package_zip() {
  ZIP="$OUTDIR/forensic_collection_$(date -u +%Y%m%d%H%M%S).zip"
  echo "Zipping artifacts -> $ZIP …"
  (cd "$OUTDIR" && zip -qr "$ZIP" .) || true
  echo "$ZIP"
}
encrypt_artifact() {
  local in="$1"
  [ -z "${ENCRYPT_PUBKEY:-}" ] && return 0
  local m="$ENCRYPT_METHOD"
  if [ "$m" = "auto" ]; then
    if command -v age >/dev/null 2>&1; then m="age"
    elif command -v gpg >/dev/null 2>&1; then m="gpg"
    else m="openssl"; fi
  fi
  echo "[encrypt] Method: $m"
  if [ "$m" = "age" ]; then
    ENCRYPTED_FILE="${in}.age"
    age -R "$ENCRYPT_PUBKEY" "$in" > "$ENCRYPTED_FILE"
    echo "[encrypt] Wrote $ENCRYPTED_FILE"; return 0
  fi
  if [ "$m" = "gpg" ]; then
    ENCRYPTED_FILE="${in}.gpg"
    gpg --yes -o "$ENCRYPTED_FILE" --encrypt --recipient "$ENCRYPT_PUBKEY" "$in"
    echo "[encrypt] Wrote $ENCRYPTED_FILE"; return 0
  fi
  if [ "$m" = "openssl" ]; then
    ENCRYPTED_FILE="${in}.enc"
    local dek="$OUTDIR/.dek.bin" iv="$OUTDIR/.iv.bin"
    openssl rand 32 > "$dek"; openssl rand 12 > "$iv"
    openssl enc -aes-256-gcm -in "$in" -out "$ENCRYPTED_FILE" \
      -K "$(xxd -p "$dek" | tr -d '\n')" -iv "$(xxd -p "$iv" | tr -d '\n')" -S 0000000000000000 -p >/dev/null 2>&1 || true
    openssl pkeyutl -encrypt -pubin -inkey "$ENCRYPT_PUBKEY" -in "$dek" -out "${ENCRYPTED_FILE}.key" >/dev/null 2>&1
    cp "$iv" "${ENCRYPTED_FILE}.iv"
    rm -f "$dek" "$iv"
    echo "[encrypt] Wrote $ENCRYPTED_FILE (+ .key, .iv)"; return 0
  fi
}
discord_upload() {
  local file_to_send="$1"
  [ -z "${DISCORD_WEBHOOK:-}" ] && return 0
  local payload='{"content":"Sequoia forensic collection","embeds":[{"title":"Artifacts","description":"Attached file (sensitive)."}]}'
  echo "Uploading to Discord…"
  curl -s -X POST "$DISCORD_WEBHOOK" \
      -F "payload_json=$payload" \
      -F "file=@${file_to_send}" \
      -o "$OUTDIR/discord_upload_status.txt" -w "%{http_code}\n" || true
  echo "Discord status: $(tail -n1 "$OUTDIR/discord_upload_status.txt")"
  coc_add_transfer "system" "Uploaded via webhook"
}

# -----------------------
# Steps
# -----------------------
STEPS=(
  "Disk imaging + hashing"
  "System snapshot"
  "Copy key system files"
  "Login activity"
  "Unified logs"
  "FSEvents"
  "Audit logs"
  "USB & mount info"
  "Network state"
  "Find recent files"
  "Collect user metadata"
  "Suspicious processes"
  "Cron & launchd inspection"
  "Sudo activity"
  "Build HTML report"
  "Package / Encrypt / Upload"
)
FUNCS=(
  "image_and_hash"
  "collect_system_snapshot"
  "collect_key_files"
  "collect_login_activity"
  "collect_unified_logs"
  "collect_fsevents"
  "collect_audit_logs"
  "collect_usb_and_mounts"
  "collect_network_state"
  "find_recent_files"
  "collect_user_metadata"
  "suspicious_procs"
  "cron_and_launchd_check"
  "sudo_activity"
  "build_html_report"
  ":" # handled specially
)

$FORENSIC_MODE && echo "[mode] Forensic mode ON: acquisition occurs before analysis."

for i in "${!STEPS[@]}"; do
  label="${STEPS[$i]}"; func="${FUNCS[$i]}"
  if $FORENSIC_MODE && ! $NO_IMAGE_OK && [ "$label" != "Disk imaging + hashing" ]; then
    $IMAGING_DONE || { echo "[guard] Acquisition not complete; re-run with --image <dev> or --no-image-ok."; exit 3; }
  fi
  if [ "$label" = "Package / Encrypt / Upload" ]; then
    ZIP="$(package_zip)"
    if [ -n "${ENCRYPT_PUBKEY:-}" ]; then encrypt_artifact "$ZIP"; SEND_FILE="${ENCRYPTED_FILE:-$ZIP}"; else SEND_FILE="$ZIP"; fi
    coc_add_transfer "local" "Packaged artifacts"
    discord_upload "$SEND_FILE"
  else
    run_step "$label" "$func"
  fi
done

# Pretty elapsed time at the end
fmt_time() { local s=$1; printf "%02d:%02d:%02d" "$((s/3600))" "$(((s%3600)/60))" "$((s%60))"; }
echo "[done] Steps completed: $RUN_COUNT/${#STEPS[@]}  total elapsed: $(fmt_time "$TOTAL_ELAPSED")"


echo; echo "[done] Output directory: $OUTDIR"
echo "[done] Log: $LOG"

echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RUN_STATUS"
echo "script_version=$SCRIPT_VERSION"            >> "$RUN_STATUS"
echo "exit_code=0"                               >> "$RUN_STATUS"

