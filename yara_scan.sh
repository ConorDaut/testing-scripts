#!/usr/bin/env bash
#
# ==============================================================================
# yara_scan.sh - Run Elastic Linux YARA rules against the entire filesystem
# ==============================================================================
# Made using Claude AI Sonnet 5.5 Medium - Still Needs Testing
# SUMMARY
#   This script must be run as root. It takes one argument: the path to a
#   directory containing YARA rules (for example, a local clone of
#   https://github.com/elastic/protections-artifacts, folder yara/rules).
#
#   What it does:
#     1. Verifies it is running as root and that the rules directory exists.
#     2. Installs YARA if it is not already installed (Ubuntu/Debian via apt,
#        Fedora via dnf).
#     3. Finds every rule file whose name starts with "Linux" (.yar / .yara).
#     4. Builds a list of every regular file on the system. Only the
#        kernel pseudo-filesystems (/proc, /sys), network mounts, the rules
#        directory, and the log directory are skipped. Device nodes are not
#        regular files, so they are never scanned, but /dev/shm, /run, /tmp,
#        etc. ARE scanned.
#     5. Runs each Linux rule file against that file list, one rule file at a
#        time, automatically.
#     6. Writes results to /var/log/syst/yara_results.log. The log is created
#        fresh on every run. Each rule file that produces hits gets a header
#        with the rule file name followed by YARA's output (matched rule name
#        and file path). Rule files with no hits add nothing to the log.
#
# USAGE
#   sudo ./yara_scan.sh /path/to/yara/rules
#
# NOTES
#   - Rule files that fail to compile (e.g., need a newer YARA version or
#     modules your YARA build lacks) are skipped with a warning on the console.
#   - A full filesystem scan with hundreds of rules can take a long time.
# ==============================================================================

set -uo pipefail

LOG_DIR="/var/log/syst"
LOG_FILE="${LOG_DIR}/yara_results.log"

# ---------- helpers ----------
log()  { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[X] $*" >&2; exit 1; }

# ---------- 1. root + argument checks ----------
[[ $EUID -eq 0 ]] || die "This script must be run as root (try: sudo $0 <rules_dir>)."

[[ $# -eq 1 ]] || die "Usage: $0 <path_to_yara_rules_directory>"

RULES_DIR="$(realpath -- "$1" 2>/dev/null)" || die "Cannot resolve path: $1"
[[ -d "$RULES_DIR" ]] || die "Rules directory not found: $RULES_DIR"

# ---------- 2. install yara if missing ----------
install_yara() {
    local id="" id_like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        id_like="${ID_LIKE:-}"
    fi

    case " $id $id_like " in
        *" ubuntu "*|*" debian "*)
            log "Detected Ubuntu/Debian. Installing yara with apt..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y yara
            ;;
        *" fedora "*)
            log "Detected Fedora. Installing yara with dnf..."
            dnf install -y yara
            ;;
        *)
            die "Unsupported distribution (ID='$id'). Only Ubuntu and Fedora are supported."
            ;;
    esac
}

if command -v yara >/dev/null 2>&1; then
    log "YARA already installed: $(yara --version 2>/dev/null)"
else
    install_yara
    command -v yara >/dev/null 2>&1 || die "YARA installation failed."
    log "YARA installed: $(yara --version 2>/dev/null)"
fi

# ---------- 3. collect Linux rule files ----------
mapfile -t RULE_FILES < <(
    find "$RULES_DIR" -type f -name 'Linux*' \( -name '*.yar' -o -name '*.yara' \) | sort
)

[[ ${#RULE_FILES[@]} -gt 0 ]] || die "No rule files starting with 'Linux' found in: $RULES_DIR"
log "Found ${#RULE_FILES[@]} Linux rule file(s)."

# ---------- prepare log (fresh each run) ----------
mkdir -p "$LOG_DIR" || die "Could not create $LOG_DIR"
: > "$LOG_FILE"     || die "Could not create $LOG_FILE"
chmod 700 "$LOG_DIR"
chmod 600 "$LOG_FILE"

# ---------- temp files + cleanup ----------
FILE_LIST="$(mktemp /tmp/yara_filelist.XXXXXX)"
ERR_TMP="$(mktemp /tmp/yara_err.XXXXXX)"
OUT_TMP="$(mktemp /tmp/yara_out.XXXXXX)"
trap 'rm -f "$FILE_LIST" "$ERR_TMP" "$OUT_TMP"' EXIT

# ---------- 4. build list of files to scan ----------
# Skipped: /proc and /sys (kernel pseudo-filesystems), network/FUSE-remote
# mounts (can hang or be huge), the rules directory (rules would match
# themselves), the log directory, and our own temp files.
# Everything else is scanned, including /dev/shm, /run, /tmp, /var, /home, etc.
log "Building list of files to scan (this may take a moment)..."
find / \
    \( -path /proc -o -path /sys \
       -o -path "$RULES_DIR" -o -path "$LOG_DIR" \
       -o -path "$FILE_LIST" -o -path "$ERR_TMP" -o -path "$OUT_TMP" \
       -o -fstype nfs -o -fstype nfs4 -o -fstype cifs -o -fstype smb3 \
       -o -fstype fuse.sshfs -o -fstype afs -o -fstype 9p \) -prune \
    -o -type f ! -name $'*\n*' -print > "$FILE_LIST" 2>/dev/null

TOTAL_FILES=$(wc -l < "$FILE_LIST")
log "Scanning $TOTAL_FILES file(s) per rule."

# ---------- choose scan method ----------
# Newer YARA (4.3+) can read a list of files directly (fast, one process per
# rule). Older versions (e.g., Ubuntu 22.04's 4.1) fall back to xargs.
THREADS="$(nproc 2>/dev/null || echo 2)"
if yara --help 2>&1 | grep -q -- '--scan-list'; then
    SCAN_METHOD="scanlist"
else
    SCAN_METHOD="xargs"
fi
log "Scan method: $SCAN_METHOD (threads: $THREADS)"

# ---------- 5. run each rule one by one ----------
HIT_RULEFILES=0
SKIPPED=0
COUNT=0

for rule in "${RULE_FILES[@]}"; do
    COUNT=$((COUNT + 1))
    rule_name="$(basename "$rule")"
    log "[$COUNT/${#RULE_FILES[@]}] $rule_name"

    # Pre-check: make sure the rule compiles; skip it if not.
    if ! yara "$rule" /dev/null >/dev/null 2>"$ERR_TMP"; then
        warn "Skipping $rule_name (failed to compile): $(head -n 1 "$ERR_TMP")"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    : > "$OUT_TMP"
    if [[ "$SCAN_METHOD" == "scanlist" ]]; then
        yara -p "$THREADS" --scan-list "$rule" "$FILE_LIST" >"$OUT_TMP" 2>/dev/null
    else
        xargs -d '\n' -a "$FILE_LIST" -n 1 -P "$THREADS" yara "$rule" >"$OUT_TMP" 2>/dev/null
    fi

    # Only write to the log if the rule produced results.
    if [[ -s "$OUT_TMP" ]]; then
        {
            echo "=== Rule file: $rule_name ==="
            cat "$OUT_TMP"
            echo
        } >> "$LOG_FILE"
        HIT_RULEFILES=$((HIT_RULEFILES + 1))
        log "    -> hits found (logged)"
    fi
done

# ---------- done ----------
log "Scan complete."
log "Rule files run: $((${#RULE_FILES[@]} - SKIPPED)) | skipped: $SKIPPED | with hits: $HIT_RULEFILES"
if [[ $HIT_RULEFILES -gt 0 ]]; then
    log "Results saved to: $LOG_FILE"
else
    log "No hits. $LOG_FILE is empty."
fi
