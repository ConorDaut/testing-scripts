#!/usr/bin/env bash
# 
# Made using Claude Sonnet 5.5 Medium
# STILL NEEDS TO BE TESTED
# nixos-config-backup.sh
# Preserve the ORIGINAL /etc/nixos/configuration.nix in 3 locations and revert to it.
#
# Usage (run as root):
#   ./nixos-config-backup.sh backup                 # save original (run BEFORE installing the new config)
#   ./nixos-config-backup.sh status                 # verify all 3 copies
#   ./nixos-config-backup.sh revert [-y] [--no-rebuild]
#
# Safety features:
#   * The original is NEVER overwritten once saved.
#   * Each copy has a SHA-256 manifest; `status`/`revert` verify and self-heal bad/missing copies.
#   * Copies are set read-only (0400) and immutable (chattr +i) where the filesystem allows.
#   * `revert` first saves the current config to /root/nixos-pre-revert/.
#   * `backup` refuses to run if configuration.nix is already the hardened PXE/SSH config.

set -euo pipefail

CONFIG_DIR="/etc/nixos"
CONFIG_FILE="${CONFIG_DIR}/configuration.nix"
HW_FILE="${CONFIG_DIR}/hardware-configuration.nix"
BACKUP_DIRS=(
  "/root/nixos-orig-backup"
  "/var/backups/nixos-orig"
  "/opt/nixos-orig-backup"
)
PRE_REVERT_DIR="/root/nixos-pre-revert"
MARKER="NIXOS-PXE-SSH-HARDENED-CONFIG"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

need_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo $0 ...)"; }

unlock() { chattr -i "$@" 2>/dev/null || true; }
lock()   { chmod 0400 "$@"; chattr +i "$@" 2>/dev/null || true; }

# A backup dir is valid when configuration.nix matches its own SHA-256 manifest.
is_valid() {
  local d=$1
  [[ -f "$d/configuration.nix" && -f "$d/configuration.nix.sha256" ]] || return 1
  (cd "$d" && sha256sum -c --status configuration.nix.sha256) 2>/dev/null
}

# Print the first valid backup dir, or return 1.
find_good() {
  local d
  for d in "${BACKUP_DIRS[@]}"; do
    if is_valid "$d"; then echo "$d"; return 0; fi
  done
  return 1
}

# Copy a verified backup (file + manifest [+ hardware config]) from $1 into dir $2.
copy_backup() {
  local src=$1 dst=$2
  mkdir -p "$dst"
  chmod 0700 "$dst"
  unlock "$dst"/configuration.nix "$dst"/configuration.nix.sha256 2>/dev/null
  cp -f "$src/configuration.nix" "$dst/configuration.nix"
  cp -f "$src/configuration.nix.sha256" "$dst/configuration.nix.sha256"
  lock "$dst/configuration.nix" "$dst/configuration.nix.sha256"
  if [[ -f "$src/hardware-configuration.nix" && ! -f "$dst/hardware-configuration.nix" ]]; then
    cp -f "$src/hardware-configuration.nix" "$dst/hardware-configuration.nix"
    lock "$dst/hardware-configuration.nix"
  fi
}

# Repair any missing/corrupt copy from a good one.
heal() {
  local good=$1 d
  for d in "${BACKUP_DIRS[@]}"; do
    [[ "$d" == "$good" ]] && continue
    if ! is_valid "$d"; then
      info "Repairing backup in $d from $good"
      copy_backup "$good" "$d"
    fi
  done
}

cmd_status() {
  local d ok=0
  for d in "${BACKUP_DIRS[@]}"; do
    if is_valid "$d"; then
      printf '  [ OK ] %s  (%s)\n' "$d" "$(cut -c1-16 "$d/configuration.nix.sha256")..."
      ok=$((ok+1))
    elif [[ -e "$d/configuration.nix" ]]; then
      printf '  [BAD ] %s  (hash mismatch or missing manifest)\n' "$d"
    else
      printf '  [MISS] %s\n' "$d"
    fi
  done
  echo "Valid copies: $ok / ${#BACKUP_DIRS[@]}"
  [[ $ok -ge 1 ]]
}

cmd_backup() {
  need_root
  local good d
  if good=$(find_good); then
    info "Original already backed up (valid copy: $good). Not overwriting."
    heal "$good"
    cmd_status
    return 0
  fi

  # Some copy exists but none verify: do not clobber potential evidence/data.
  for d in "${BACKUP_DIRS[@]}"; do
    [[ -e "$d/configuration.nix" ]] && \
      die "Backup exists in $d but fails verification. Inspect it manually; refusing to overwrite."
  done

  [[ -f "$CONFIG_FILE" ]] || die "$CONFIG_FILE not found."
  if grep -q "$MARKER" "$CONFIG_FILE"; then
    die "$CONFIG_FILE already contains the hardened PXE/SSH config. That is not the original; refusing to back it up as such."
  fi

  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  cp -p "$CONFIG_FILE" "$tmp/configuration.nix"
  [[ -f "$HW_FILE" ]] && cp -p "$HW_FILE" "$tmp/hardware-configuration.nix"
  (cd "$tmp" && sha256sum configuration.nix > configuration.nix.sha256)

  for d in "${BACKUP_DIRS[@]}"; do
    info "Saving original to $d"
    copy_backup "$tmp" "$d"
  done

  echo
  cmd_status
  info "Original saved. Copies are read-only/immutable; to delete one deliberately: chattr -i <file>"
}

cmd_revert() {
  need_root
  local assume_yes=0 do_rebuild=1 arg
  for arg in "$@"; do
    case "$arg" in
      -y|--yes)      assume_yes=1 ;;
      --no-rebuild)  do_rebuild=0 ;;
      *) die "Unknown option: $arg" ;;
    esac
  done

  local good
  good=$(find_good) || die "No valid backup of the original found. Run '$0 status'."
  heal "$good"

  if [[ $assume_yes -eq 0 ]]; then
    read -r -p "Revert $CONFIG_FILE to the ORIGINAL and rebuild? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
  fi

  if [[ -f "$CONFIG_FILE" ]]; then
    mkdir -p "$PRE_REVERT_DIR"
    local saved="$PRE_REVERT_DIR/configuration.nix.$(date +%Y%m%d-%H%M%S)"
    cp -p "$CONFIG_FILE" "$saved"
    info "Current config saved to $saved"
  fi

  install -m 0644 "$good/configuration.nix" "$CONFIG_FILE"
  info "Original restored from $good"

  if [[ $do_rebuild -eq 1 ]]; then
    info "Running: nixos-rebuild switch"
    nixos-rebuild switch || die "nixos-rebuild failed. Original file is in place; check the output above."
    info "Reverted and rebuilt successfully."
  else
    info "Skipped rebuild (--no-rebuild). Run: nixos-rebuild switch"
  fi
}

usage() {
  sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

case "${1:-}" in
  backup) cmd_backup ;;
  status) need_root; cmd_status ;;
  revert) shift; cmd_revert "$@" ;;
  *)      usage ;;
esac
