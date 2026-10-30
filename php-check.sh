#!/bin/sh
# =============================================================================
# php-check.sh
# =============================================================================
# Made using Claude Sonnet 5.5 Medium
# STILL REQUIRES TESTING
# PURPOSE
#   Checks a Linux host for PHP, determines whether the installed PHP is
#   vulnerable to "php2shell" (CVE-2026-109618 / CVE-2026-109619), updates PHP
#   to a protected release when possible, verifies the result, and offers to
#   restart every service that relies on PHP.
#
# STEPS (each prints a blue title)
#   1. Check whether PHP is installed (CLI, FPM, CGI, mod_php packages)
#   2. Check whether each installed PHP branch is vulnerable
#        a) Look in the package changelog for BOTH CVE IDs (distros usually
#           backport the fix without changing the upstream version number)
#        b) Otherwise fall back to comparing against the fixed upstream versions:
#              8.5 -> 8.5.12   8.4 -> 8.4.27   8.3 -> 8.3.36   8.2 -> 8.2.35
#           PHP 8.1 and older are end-of-life upstream (no official fix).
#   3. Update PHP packages (distro repositories first; third-party repositories
#      only if you answer "y" at the prompt or pass --third-party)
#   4. Verify the installed version is protected, then ask (y/n) before
#      restarting PHP-dependent services (php-fpm, apache2/httpd, nginx,
#      lighttpd, Caddy, FrankenPHP, LiteSpeed). Roundcube runs under Apache or
#      FPM, so restarting those covers it.
#
# SUPPORTED SYSTEMS
#   Debian, Ubuntu, Kali Linux      (apt)
#   Rocky Linux, Fedora             (dnf; RHEL/Alma/CentOS also work)
#   Alpine Linux                    (apk; bash is installed automatically)
#   VyOS                            (DETECT AND REPORT ONLY - no changes made)
#   Arch Linux and derivatives      (pacman; needs a FULL system upgrade)
#   OPNsense (FreeBSD)              (pkg; bash is installed automatically)
#   Tiny Core Linux                 (tce-update; fix loads after a reboot)
#
# USAGE
#   sudo ./php-check.sh [options]
#     -y, --yes          Restart services without asking (does NOT auto-approve
#                        third-party repositories)
#         --third-party  Allow adding a third-party repo (Sury / Remi) if the
#                        distro repositories do not have the fix yet
#         --full-upgrade Approve the full system/package upgrade that Arch
#                        (pacman -Syu) and OPNsense (pkg upgrade) require
#         --dry-run      Show what would be done; change nothing
#     -h, --help         Show this help
#
# DESIGN NOTES
#   * Must be run as root.
#   * EOL branches (PHP 8.1 and older): the script only tries an in-branch
#     upgrade from the distro (e.g. an Ubuntu/RHEL backport). It NEVER moves you
#     to a newer major/minor branch, since that can break applications. If the
#     branch is still unprotected afterwards, it stops and reports the problem.
#   * Debian/Ubuntu packages may restart some services on their own during the
#     upgrade (package post-install scripts). Step 4 restarts the rest.
#   * Arch Linux does not support partial upgrades, so fixing PHP means a full
#     'pacman -Syu'. The script asks first (or use --full-upgrade).
#   * OPNsense: the officially recommended way to update is System > Firmware >
#     Updates in the web GUI. The CLI route used here is a full 'pkg upgrade'
#     (asks first, or use --full-upgrade). Fixed releases: Community 26.7.7
#     (PHP 8.5.12) and Business 26.4.2p3 (PHP 8.3.36). Afterwards the web GUI
#     and, if configured, the captive portal are restarted.
#   * Tiny Core Linux: tce-load/tce-update refuse to run as root, so they are run
#     as user "tc". Updated extensions are only STAGED and load at next boot, so
#     the script offers a reboot; run it again afterwards to verify. Needs a
#     persistent TCE directory.
#   * A log of everything run is written to /var/log/php-check.log
#
# EXIT CODES
#   0 protected / nothing to do      1 non-fatal command error(s) occurred
#   2 not root or unsupported OS     3 EOL PHP branch still unprotected
#   4 PHP still vulnerable          6 update staged, reboot required (Tiny Core)
# =============================================================================

# --- Bootstrap: this script needs bash (Alpine ships only ash by default) ----
if [ -z "${BASH_VERSION:-}" ]; then
    if ! command -v bash >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            echo "bash not found - installing it (Alpine)..."
            apk add --no-cache bash >/dev/null 2>&1 || {
                echo "ERROR: could not install bash (are you root?)"; exit 1; }
        elif [ -d /usr/local/opnsense ] && command -v pkg >/dev/null 2>&1; then
            echo "bash not found - installing it (OPNsense)..."
            pkg install -y bash >/dev/null 2>&1 || {
                echo "ERROR: could not install bash (are you root?)"; exit 1; }
        elif command -v tce-load >/dev/null 2>&1; then
            # Tiny Core: tce-load must run as the unprivileged user "tc"
            echo "bash not found - installing it (Tiny Core)..."
            if command -v sudo >/dev/null 2>&1; then
                sudo -u tc tce-load -wi bash.tcz >/dev/null 2>&1
            else
                su tc -c "tce-load -wi bash.tcz" >/dev/null 2>&1
            fi || { echo "ERROR: could not install bash."; exit 1; }
        else
            echo "ERROR: bash is required to run this script."; exit 1
        fi
    fi
    exec bash "$0" "$@"
fi

# =============================================================================
# Settings and globals
# =============================================================================
LOG_FILE="/var/log/php-check.log"
CVE_1="CVE-2026-109618"
CVE_2="CVE-2026-109619"

# First upstream release that contains the fix, per supported branch.
declare -A FIXED_VERSION=( [8.2]="8.2.35" [8.3]="8.3.36" [8.4]="8.4.27" [8.5]="8.5.12" )

# Per-branch state, filled in by detect_php / evaluate_branch:
declare -A BRANCH_VER BRANCH_STATUS BRANCH_REASON   # status: PROTECTED|VULNERABLE|EOL

ASSUME_YES=0; ALLOW_THIRD_PARTY=0; DRY_RUN=0; FULL_UPGRADE=0
REBOOT_NEEDED=0                # 1 on Tiny Core after staging an update
OPNSENSE=0                     # 1 when running on OPNsense
ERRORS=0                       # count of non-fatal command failures
PM=""; PM_BIN=""               # package manager (apt|dnf|apk|pacman|pkg|tce|none) and binary
REPORT_ONLY=0                  # 1 on VyOS: never change anything
OS_ID=""; OS_VERSION_ID=""; OS_CODENAME=""; OS_PRETTY=""
INIT=""                        # systemd | openrc | sysv | opnsense | tce
ALL_PKGS=()                    # installed PHP-related packages

# =============================================================================
# Colors (only when writing to a terminal)
#   Blue = step titles, Green = important successes, Red = failures,
#   Yellow = warnings/notes
# =============================================================================
if [ -t 1 ]; then
    BLUE=$'\033[1;94m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'
    YELLOW=$'\033[1;33m'; RESET=$'\033[0m'
else
    BLUE=""; GREEN=""; RED=""; YELLOW=""; RESET=""
fi

log()   { echo "$(date '+%F %T') $*" >> "$LOG_FILE" 2>/dev/null; }
title() { printf '\n%s==> %s%s\n' "$BLUE" "$*" "$RESET"; log "STEP: $*"; }
ok()    { printf '%s[ OK ]%s %s%s%s\n' "$GREEN" "$RESET" "$GREEN" "$*" "$RESET"; log "OK: $*"; }
info()  { printf '       %s\n' "$*"; log "INFO: $*"; }
warn()  { printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*"; log "WARN: $*"; }
fail()  { printf '%s[FAIL] %s%s\n' "$RED" "$*" "$RESET"; log "FAIL: $*"; }

usage() { sed -n '/^# USAGE/,/^# DESIGN/p' "$0" | sed '$d'; }

# =============================================================================
# Helper functions
# =============================================================================

# ask_yn "question" -> returns 0 for yes, 1 for no (default no; no TTY = no)
ask_yn() {
    local reply
    if [ ! -t 0 ]; then
        info "Non-interactive shell, answering 'no' to: $1"
        return 1
    fi
    read -r -p "$1 [y/N]: " reply
    [[ $reply =~ ^[Yy]([Ee][Ss])?$ ]]
}

# run_cmd "description" command args...
#   Runs a command, logs its output, and on failure prints the exit code and
#   the last lines of output in red. Honors --dry-run.
run_cmd() {
    local desc=$1 out rc; shift
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] would run: $*"
        return 0
    fi
    info "$desc ..."
    out=$("$@" 2>&1); rc=$?
    { echo "--- $*"; echo "$out"; } >> "$LOG_FILE" 2>/dev/null
    if [ $rc -ne 0 ]; then
        fail "$desc failed (exit code $rc): $*"
        printf '%s\n' "$out" | tail -n 8 | sed "s/^/       ${RED}|${RESET} /"
        ERRORS=$((ERRORS + 1))
        return $rc
    fi
    return 0
}

# ver_ge A B -> success if version A >= version B (pure bash, numeric x.y.z)
ver_ge() {
    local IFS=. i x y
    local -a a=($1) b=($2)
    for i in 0 1 2; do
        x=${a[i]:-0}; y=${b[i]:-0}
        (( 10#$x > 10#$y )) && return 0
        (( 10#$x < 10#$y )) && return 1
    done
    return 0
}

# =============================================================================
# Step 0: preflight - root check, OS and package-manager detection
# =============================================================================
preflight() {
    title "Step 0: Preflight checks"

    # The script changes packages and restarts services, so it needs root.
    if [ "$(id -u)" -ne 0 ]; then
        fail "This script must be run as root (try: sudo $0). Exit code 2."
        exit 2
    fi
    touch "$LOG_FILE" 2>/dev/null

    # Read distro info from /etc/os-release in subshells so we don't clobber vars.
    if [ -r /etc/os-release ]; then
        OS_ID=$(. /etc/os-release; echo "${ID:-unknown}")
        OS_VERSION_ID=$(. /etc/os-release; echo "${VERSION_ID:-}")
        OS_CODENAME=$(. /etc/os-release; echo "${VERSION_CODENAME:-}")
        OS_PRETTY=$(. /etc/os-release; echo "${PRETTY_NAME:-$ID}")
    fi
    local like; like=$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")

    # Appliance/special systems are detected first: several of them look like
    # another OS (VyOS = Debian) or have no /etc/os-release (OPNsense).
    if [ -f /etc/vyos-release ] || [ -d /opt/vyatta ] || [ "$OS_ID" = "vyos" ] \
       || grep -qi vyos /etc/os-release 2>/dev/null; then
        # VyOS is Debian-based but is an appliance: report only.
        OS_ID="vyos"; OS_PRETTY="VyOS"; PM="none"; REPORT_ONLY=1
    elif [ -d /usr/local/opnsense ] || command -v opnsense-version >/dev/null 2>&1; then
        # OPNsense (FreeBSD): packages are managed with pkg.
        OS_ID="opnsense"; PM="pkg"; OPNSENSE=1
        OS_PRETTY=$(opnsense-version 2>/dev/null | head -n1)
        [ -n "$OS_PRETTY" ] || OS_PRETTY="OPNsense"
    elif command -v tce-load >/dev/null 2>&1 || [ -d /etc/sysconfig/tcedir ]; then
        # Tiny Core Linux: PHP comes as .tcz extensions.
        OS_ID="tinycore"; OS_PRETTY="Tiny Core Linux"; PM="tce"
    else
        case "$OS_ID" in
            debian|ubuntu|kali)             PM="apt" ;;
            rocky|fedora|rhel|almalinux|centos) PM="dnf" ;;
            alpine)                         PM="apk" ;;
            arch|manjaro|endeavouros|garuda|cachyos|artix) PM="pacman" ;;
            *)  # Fall back to ID_LIKE for derivatives (Mint, Raspbian, Oracle...)
                case " $like " in
                    *" debian "*|*" ubuntu "*)        PM="apt" ;;
                    *" rhel "*|*" fedora "*|*" centos "*) PM="dnf" ;;
                    *" arch "*)                       PM="pacman" ;;
                    *) PM="" ;;
                esac ;;
        esac
    fi

    if [ "$PM" = "dnf" ]; then
        # Older RHEL-family systems only have yum; the syntax we use is the same.
        if command -v dnf >/dev/null 2>&1; then PM_BIN=dnf; else PM_BIN=yum; fi
    fi

    if [ -z "$PM" ]; then
        fail "Unsupported OS: '$OS_ID'. Supported: Debian, Ubuntu, Kali, Rocky, Fedora, Alpine, Arch, OPNsense, Tiny Core, VyOS. Exit code 2."
        exit 2
    fi

    # Which init system manages services (used in Step 4).
    if [ "$OPNSENSE" -eq 1 ]; then INIT=opnsense
    elif [ "$PM" = "tce" ]; then INIT=tce
    elif [ -d /run/systemd/system ]; then INIT=systemd
    elif command -v rc-service >/dev/null 2>&1; then INIT=openrc
    else INIT=sysv; fi

    ok "Running as root on ${OS_PRETTY:-$OS_ID} (package manager: $PM, init: $INIT)"
    [ "$REPORT_ONLY" -eq 1 ] && warn "VyOS detected: detect-and-report mode, no changes will be made."
    [ "$DRY_RUN" -eq 1 ] && warn "Dry-run mode: no changes will be made."
}

# =============================================================================
# PHP discovery
# =============================================================================

# list_php_pkgs: fill ALL_PKGS with installed PHP-related package names.
list_php_pkgs() {
    ALL_PKGS=()
    case "$PM" in
        apt)
            mapfile -t ALL_PKGS < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' \
                'php*' 'libapache2-mod-php*' 2>/dev/null | awk '$1=="ii"{print $2}' | sort -u) ;;
        dnf)
            # Matches php, php-cli, mod_php, and Remi-style php83-php-* names,
            # but not unrelated packages such as phpMyAdmin.
            mapfile -t ALL_PKGS < <(rpm -qa --qf '%{NAME}\n' 2>/dev/null \
                | grep -E '^(mod_)?php[0-9.]*(-[a-z0-9._+-]+)?$' | sort -u) ;;
        apk)
            mapfile -t ALL_PKGS < <(apk info 2>/dev/null | grep -E '^php[0-9]*(-.*)?$' | sort -u) ;;
        pacman)   # Arch: php, php-fpm, php-apache, php-cgi ... (legacy: php82, php82-fpm)
            mapfile -t ALL_PKGS < <(pacman -Qq 2>/dev/null \
                | grep -E '^php[0-9]*(-[a-z0-9._+-]+)?$' | sort -u) ;;
        pkg)      # OPNsense/FreeBSD: php85, php85-session ...
            mapfile -t ALL_PKGS < <(pkg query '%n' 2>/dev/null \
                | grep -E '^php[0-9]*(-[a-z0-9._+-]+)?$' | sort -u) ;;
        tce)      # Tiny Core keeps one marker file per loaded extension here
            mapfile -t ALL_PKGS < <(ls /usr/local/tce.installed 2>/dev/null \
                | grep -E '^php' | sort -u) ;;
    esac
}

# pkgs_for_branch 8.3 -> prints installed packages that belong to that branch
#   Debian/Ubuntu: php8.3-*   Alpine/Remi: php83-*   RHEL/Fedora native: php-*
pkgs_for_branch() {
    local branch=$1 nodot=${1//./} p
    local -a out=()
    for p in "${ALL_PKGS[@]}"; do
        case "$p" in *php"$branch"*|*php"$nodot"*|*php-"$branch"*) out+=("$p") ;; esac
    done
    # Distros that use unversioned names (RHEL/Rocky/Fedora native PHP)
    if [ ${#out[@]} -eq 0 ]; then
        for p in "${ALL_PKGS[@]}"; do
            case "$p" in php|php-*|mod_php*|libapache2-mod-php) out+=("$p") ;; esac
        done
    fi
    [ ${#out[@]} -gt 0 ] && printf '%s\n' "${out[@]}"
}

# add_version X.Y.Z -> record it under its branch, keeping the LOWEST version
# seen per branch (the weakest component decides if the branch is protected).
add_version() {
    local ver=$1 branch=${1%.*} cur=${BRANCH_VER[${1%.*}]:-}
    if [ -z "$cur" ] || ! ver_ge "$ver" "$cur"; then BRANCH_VER[$branch]=$ver; fi
}

# detect_php: find every PHP binary / package and record branch -> version.
detect_php() {
    BRANCH_VER=(); BRANCH_STATUS=(); BRANCH_REASON=()
    list_php_pkgs
    local -A seen=()
    local -a cands=()
    local b p real out ver pkg re
    re='PHP ([0-9]+\.[0-9]+\.[0-9]+)'

    # Candidate binaries: CLI, CGI, FPM, versioned (php8.3, php83) and Remi paths.
    for b in php php-cgi php-fpm; do
        p=$(command -v "$b" 2>/dev/null) && cands+=("$p")
    done
    for p in /usr/bin/php[0-9]* /usr/bin/php-cgi[0-9]* /usr/sbin/php-fpm* \
             /usr/sbin/php[0-9]*-fpm /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm \
             /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm; do
        [ -f "$p" ] && [ -x "$p" ] && cands+=("$p")
    done

    for p in "${cands[@]}"; do
        real=$(readlink -f "$p" 2>/dev/null || echo "$p")
        [ -n "${seen[$real]:-}" ] && continue
        seen[$real]=1
        out=$("$p" -v 2>/dev/null | head -n1)
        if [[ $out =~ $re ]]; then add_version "${BASH_REMATCH[1]}"; fi
    done

    # Fallback: no binary found (e.g. only the Apache mod_php package is
    # installed), so read the version from package metadata instead.
    if [ ${#BRANCH_VER[@]} -eq 0 ] && [ ${#ALL_PKGS[@]} -gt 0 ]; then
        re='^([0-9]+\.[0-9]+\.[0-9]+)'
        for pkg in "${ALL_PKGS[@]}"; do
            # Only core-looking packages, to avoid reading versions of PHP libraries
            [[ $pkg =~ ^(lib)?(apache2-mod-)?(mod_)?php([0-9.]+)?(-php)?(-(common|cli|fpm|cgi))?$ ]] || continue
            case "$PM" in
                apt) ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null) ;;
                dnf) ver=$(rpm -q --qf '%{VERSION}' "$pkg" 2>/dev/null) ;;
                apk) ver=$(apk info -v "$pkg" 2>/dev/null | head -n1 | sed "s/^$pkg-//") ;;
                pacman) ver=$(pacman -Q "$pkg" 2>/dev/null | awk '{print $2}') ;;
                pkg) ver=$(pkg query '%v' "$pkg" 2>/dev/null) ;;
                *)   ver="" ;;   # Tiny Core names carry no patch level
            esac
            [[ $ver =~ $re ]] && add_version "${BASH_REMATCH[1]}"
        done
    fi
}

# =============================================================================
# Vulnerability evaluation
# =============================================================================

# changelog_mentions_cves pkg... -> success if a package changelog references
# BOTH CVE IDs (i.e. the distro backported the fix).
changelog_mentions_cves() {
    local pkg f text
    for pkg in "$@"; do
        text=""
        case "$PM" in
            apt)
                # Read each changelog file that dpkg says belongs to the package.
                while read -r f; do
                    [ -f "$f" ] && text+=$(gzip -dcf "$f" 2>/dev/null)
                done < <(dpkg-query -L "$pkg" 2>/dev/null | grep -E '/changelog(\.Debian)?(\.gz)?$') ;;
            dnf) text=$(rpm -q --changelog "$pkg" 2>/dev/null) ;;
            *)   return 1 ;;   # Alpine has no local changelog -> version check only
        esac
        if grep -q "$CVE_1" <<<"$text" && grep -q "$CVE_2" <<<"$text"; then return 0; fi
    done
    return 1
}

# evaluate_branch 8.3 -> sets BRANCH_STATUS / BRANCH_REASON for that branch
evaluate_branch() {
    local branch=$1 ver=${BRANCH_VER[$1]} fixed=${FIXED_VERSION[$1]:-}
    local maj=${1%%.*} min=${1##*.}
    local -a pk=()
    mapfile -t pk < <(pkgs_for_branch "$branch")

    # (a) Changelog first: a distro backport protects even "old" version numbers.
    if changelog_mentions_cves "${pk[@]}"; then
        BRANCH_STATUS[$branch]="PROTECTED"
        BRANCH_REASON[$branch]="package changelog references $CVE_1 and $CVE_2 (distro backport)"
        return
    fi
    # (b) End-of-life upstream and no distro fix found.
    if (( maj < 8 || (maj == 8 && min < 2) )); then
        BRANCH_STATUS[$branch]="EOL"
        BRANCH_REASON[$branch]="PHP $branch is end-of-life: no official fix and no distro backport found"
        return
    fi
    # (c) Fall back to comparing with the fixed upstream version.
    if [ -n "$fixed" ]; then
        if ver_ge "$ver" "$fixed"; then
            BRANCH_STATUS[$branch]="PROTECTED"
            BRANCH_REASON[$branch]="version $ver is at or above the fixed release $fixed"
        else
            BRANCH_STATUS[$branch]="VULNERABLE"
            BRANCH_REASON[$branch]="version $ver is below fixed release $fixed and no changelog entry for the CVEs"
        fi
    else
        # A branch newer than any listed above (e.g. a future 8.6).
        BRANCH_STATUS[$branch]="PROTECTED"
        BRANCH_REASON[$branch]="branch $branch is newer than the known-affected branches (verify manually)"
    fi
}

# refresh_state: re-detect PHP and re-evaluate every branch (used after updates)
refresh_state() {
    detect_php
    local b
    for b in "${!BRANCH_VER[@]}"; do evaluate_branch "$b"; done
}

# print_state: show each branch result (green when protected, red otherwise)
print_state() {
    local b
    for b in $(printf '%s\n' "${!BRANCH_VER[@]}" | sort); do
        case "${BRANCH_STATUS[$b]}" in
            PROTECTED)  ok   "PHP $b (${BRANCH_VER[$b]}): PROTECTED - ${BRANCH_REASON[$b]}" ;;
            VULNERABLE) fail "PHP $b (${BRANCH_VER[$b]}): VULNERABLE - ${BRANCH_REASON[$b]}" ;;
            EOL)        fail "PHP $b (${BRANCH_VER[$b]}): END-OF-LIFE / UNPATCHED - ${BRANCH_REASON[$b]}" ;;
        esac
    done
}

# =============================================================================
# Updating
# =============================================================================
pm_refresh() {
    case "$PM" in
        apt) run_cmd "Refreshing package index" apt-get update ;;
        dnf) run_cmd "Refreshing package metadata" "$PM_BIN" -y makecache ;;
        apk) run_cmd "Refreshing package index" apk update ;;
        pacman) info "Arch: no standalone database sync (partial upgrades are unsupported); 'pacman -Syu' syncs and upgrades together." ;;
        pkg) run_cmd "Refreshing package catalogue" pkg update -f ;;
        tce) : ;;   # tce-update contacts the mirror itself
    esac
}

# Tiny Core: tce-load / tce-update refuse to run as root, so run them as user "tc".
tce_as_tc() {
    if command -v sudo >/dev/null 2>&1; then sudo -u tc "$@" </dev/null
    else su tc -c "$*" </dev/null; fi
}

# tce_update_exts ext... -> stage an update for each installed extension.
# The new .tcz is downloaded now but only loaded at the next boot.
tce_update_exts() {
    local dir=/etc/sysconfig/tcedir/optional ext rc=0
    if [ ! -d "$dir" ]; then
        fail "No persistent TCE directory ($dir): updates would be lost at reboot."
        ERRORS=$((ERRORS + 1)); return 1
    fi
    for ext in "$@"; do
        if [ ! -f "$dir/$ext.tcz" ]; then warn "$ext.tcz not found in $dir - skipped."; continue; fi
        run_cmd "Staging update for $ext.tcz" tce_as_tc tce-update update "$dir/$ext.tcz" || rc=1
    done
    return $rc
}

# pm_upgrade pkg... -> upgrade ONLY the named packages, never installing new ones
# and never crossing to a different PHP branch (package names are branch-specific).
pm_upgrade() {
    case "$PM" in
        apt) run_cmd "Upgrading: $*" env DEBIAN_FRONTEND=noninteractive \
                 apt-get install --only-upgrade -y \
                 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" ;;
        dnf) run_cmd "Upgrading: $*" "$PM_BIN" -y upgrade "$@" ;;
        apk) run_cmd "Upgrading: $*" apk add --upgrade "$@" ;;
        pacman)
            warn "Arch does not support partial upgrades: this needs a FULL system upgrade (pacman -Syu)."
            if [ "$DRY_RUN" -eq 1 ] || [ "$FULL_UPGRADE" -eq 1 ] || ask_yn "Run 'pacman -Syu' now?"; then
                run_cmd "Full system upgrade (pacman -Syu)" pacman -Syu --noconfirm
            else
                info "Skipped (use --full-upgrade to approve automatically)."; return 1
            fi ;;
        pkg)
            warn "OPNsense normally updates PHP via System > Firmware > Updates (recommended)."
            warn "The CLI route used here is a FULL package upgrade (pkg upgrade), not only PHP."
            if [ "$DRY_RUN" -eq 1 ] || [ "$FULL_UPGRADE" -eq 1 ] || ask_yn "Run 'pkg upgrade' now?"; then
                run_cmd "Full package upgrade (pkg upgrade)" pkg upgrade -y
            else
                info "Skipped (use --full-upgrade to approve automatically)."; return 1
            fi ;;
        tce) tce_update_exts "$@" ;;
    esac
}

# third_party_name -> human-readable name of the third-party repo for this OS
third_party_name() {
    case "$OS_ID" in
        ubuntu)                  echo "Ondrej Sury PPA (ppa:ondrej/php)" ;;
        debian)                  echo "Sury repository (packages.sury.org)" ;;
        rocky|rhel|almalinux|centos|fedora) echo "Remi's RPM repository (rpms.remirepo.net)" ;;
        *)                       echo "" ;;
    esac
}

# add_thirdparty_repo branch... -> configure the third-party repo, keep the branch
add_thirdparty_repo() {
    local rel=${OS_VERSION_ID%%.*} b
    case "$OS_ID" in
        ubuntu)
            run_cmd "Installing add-apt-repository" env DEBIAN_FRONTEND=noninteractive \
                apt-get install -y software-properties-common || return 1
            run_cmd "Adding ppa:ondrej/php" add-apt-repository -y ppa:ondrej/php || return 1
            ;;
        debian)
            run_cmd "Installing prerequisites" env DEBIAN_FRONTEND=noninteractive \
                apt-get install -y ca-certificates curl || return 1
            run_cmd "Downloading Sury signing key" curl -fsSLo /tmp/debsuryorg-archive-keyring.deb \
                https://packages.sury.org/debsuryorg-archive-keyring.deb || return 1
            run_cmd "Installing Sury signing key" dpkg -i /tmp/debsuryorg-archive-keyring.deb || return 1
            if [ "$DRY_RUN" -eq 0 ]; then
                echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ ${OS_CODENAME} main" \
                    > /etc/apt/sources.list.d/php-sury.list
            fi
            ;;
        rocky|rhel|almalinux|centos)
            run_cmd "Installing EPEL" "$PM_BIN" -y install epel-release || return 1
            run_cmd "Installing Remi repo" "$PM_BIN" -y install \
                "https://rpms.remirepo.net/enterprise/remi-release-${rel}.rpm" || return 1
            # Keep the SAME branch by selecting Remi's matching module stream.
            for b in "$@"; do
                "$PM_BIN" -y module reset php >/dev/null 2>&1
                run_cmd "Enabling Remi stream php:remi-$b" "$PM_BIN" -y module enable "php:remi-$b"
            done
            ;;
        fedora)
            run_cmd "Installing Remi repo" "$PM_BIN" -y install \
                "https://rpms.remirepo.net/fedora/remi-release-${OS_VERSION_ID}.rpm" || return 1
            for b in "$@"; do
                "$PM_BIN" -y module reset php >/dev/null 2>&1
                "$PM_BIN" -y module enable "php:remi-$b" >/dev/null 2>&1   # not needed on every release
            done
            ;;
        *)
            fail "No supported third-party repository for '$OS_ID'. Update PHP manually."
            return 1 ;;
    esac
    pm_refresh
}

# =============================================================================
# Services
# =============================================================================

# Regexes for service names, in the order they should be restarted:
# PHP workers first, then the web servers that talk to them.
SERVICE_PATTERNS=(
    '^php[0-9.]*-fpm$'        # Debian/Ubuntu/Kali: php8.3-fpm
    '^php-fpm[0-9]*$'         # Rocky/Fedora: php-fpm   Alpine: php-fpm83
    '^php[0-9]+-php-fpm$'     # Remi: php83-php-fpm
    '^lsphp'                  # LiteSpeed PHP
    '^apache2[.0-9]*$' '^httpd$'   # Apache (Debian-style / RHEL-/Arch-style / Tiny Core)
    '^nginx$' '^lighttpd$'
    '^caddy$' '^frankenphp$'
    '^webgui$' '^captiveportal$'   # OPNsense GUI (runs on PHP) and captive portal
    '^lshttpd$' '^lsws$' '^litespeed$'   # LiteSpeed
)

# list_active_services: print the names of running services for the init system
list_active_services() {
    local s f
    case "$INIT" in
        systemd)
            systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
                | awk '{print $1}' | sed 's/\.service$//' ;;
        openrc)
            for s in $(rc-service -l 2>/dev/null); do
                rc-service "$s" status >/dev/null 2>&1 && echo "$s"
            done ;;
        sysv)
            for f in /etc/init.d/*; do
                s=$(basename "$f")
                service "$s" status >/dev/null 2>&1 && echo "$s"
            done ;;
        opnsense)
            # The web GUI always runs on PHP; the captive portal only if configured.
            echo webgui
            grep -q '<captiveportal' /conf/config.xml 2>/dev/null && echo captiveportal ;;
        tce)
            # Tiny Core extensions ship init scripts in /usr/local/etc/init.d
            for f in /usr/local/etc/init.d/*; do
                [ -x "$f" ] || continue
                s=$(basename "$f")
                "$f" status >/dev/null 2>&1 && echo "$s"
            done ;;
    esac
}

service_cmd() {   # service_cmd <restart|is-active> name
    case "$INIT" in
        systemd) systemctl "$1" "$2" >/dev/null 2>&1 ;;
        openrc)  if [ "$1" = "is-active" ]; then rc-service "$2" status >/dev/null 2>&1
                 else rc-service "$2" "$1"; fi ;;
        sysv)    if [ "$1" = "is-active" ]; then service "$2" status >/dev/null 2>&1
                 else service "$2" "$1"; fi ;;
        opnsense)
            case "$1:$2" in
                restart:webgui)
                    if [ -x /usr/local/etc/rc.restart_webgui ]; then /usr/local/etc/rc.restart_webgui >/dev/null 2>&1
                    else configctl webgui restart >/dev/null 2>&1; fi ;;
                restart:captiveportal) configctl captiveportal restart >/dev/null 2>&1 ;;
                is-active:webgui) pgrep -f 'lighttpd|nginx|php-cgi|php-fpm' >/dev/null 2>&1 ;;
                *) return 0 ;;
            esac ;;
        tce)     if [ "$1" = "is-active" ]; then "/usr/local/etc/init.d/$2" status >/dev/null 2>&1
                 else "/usr/local/etc/init.d/$2" restart; fi ;;
    esac
}

# =============================================================================
# The four steps
# =============================================================================
step1_check_installed() {
    title "Step 1: Checking whether PHP is installed"
    list_php_pkgs
    detect_php
    if [ ${#BRANCH_VER[@]} -eq 0 ]; then
        if [ ${#ALL_PKGS[@]} -gt 0 ]; then
            warn "PHP packages are installed (${ALL_PKGS[*]}) but no version could be read."
            fail "Cannot determine the PHP version. Exit code 1."
            exit 1
        fi
        ok "PHP is not installed on this system - nothing to do."
        exit 0
    fi
    local b
    for b in $(printf '%s\n' "${!BRANCH_VER[@]}" | sort); do
        ok "Found PHP $b (version ${BRANCH_VER[$b]})"
    done
    [ ${#ALL_PKGS[@]} -gt 0 ] && info "Packages: ${ALL_PKGS[*]}"
}

step2_check_vulnerable() {
    title "Step 2: Checking for php2shell ($CVE_1 / $CVE_2)"
    local b
    for b in "${!BRANCH_VER[@]}"; do evaluate_branch "$b"; done
    print_state
}

step3_update() {
    title "Step 3: Updating PHP to a protected version"

    if [ "$REPORT_ONLY" -eq 1 ]; then
        warn "VyOS is an appliance: no changes made. If PHP is vulnerable here, update VyOS itself"
        warn "(add system image) or remove PHP rather than changing packages in place."
        return
    fi

    # Collect the packages of every branch that is not yet protected.
    local b p
    local -a targets=() pkgs=()
    for b in "${!BRANCH_VER[@]}"; do
        [ "${BRANCH_STATUS[$b]}" != "PROTECTED" ] && targets+=("$b")
    done
    if [ ${#targets[@]} -eq 0 ]; then
        ok "All installed PHP branches are already protected - no update needed."
        return
    fi
    for b in "${targets[@]}"; do
        while read -r p; do [ -n "$p" ] && pkgs+=("$p"); done < <(pkgs_for_branch "$b")
    done
    mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | sed '/^$/d' | sort -u)
    if [ ${#pkgs[@]} -eq 0 ]; then
        fail "No PHP packages found to update (PHP may be a manual/source install). Update it manually."
        ERRORS=$((ERRORS + 1))
        return
    fi

    info "Updating within the current branch(es) only: ${targets[*]}"
    pm_refresh
    pm_upgrade "${pkgs[@]}"
    [ "$DRY_RUN" -eq 1 ] && return

    # Tiny Core only stages updates; they load at the next boot, so we cannot
    # re-check the running version yet.
    if [ "$PM" = "tce" ]; then
        REBOOT_NEEDED=1
        warn "Tiny Core updates are staged and load at next boot. Reboot, then re-run this script to verify."
        return
    fi
    refresh_state

    # If a supported branch is still vulnerable, the distro has no fix yet.
    local -a still=()
    for b in "${!BRANCH_VER[@]}"; do
        [ "${BRANCH_STATUS[$b]}" = "VULNERABLE" ] && still+=("$b")
    done
    if [ ${#still[@]} -gt 0 ]; then
        local tp; tp=$(third_party_name)
        warn "The distro repositories do not (yet) provide the fix for PHP ${still[*]}."
        [ "$OPNSENSE" -eq 1 ] && info "OPNsense fixes: Community 26.7.7 (PHP 8.5.12), Business 26.4.2p3 (PHP 8.3.36) - upgrade to those releases or newer."
        if [ -z "$tp" ]; then
            fail "No third-party repository option for $OS_ID. Wait for an official update (or move to a newer release), or build from source."
        elif [ "$ALLOW_THIRD_PARTY" -eq 1 ] || ask_yn "Add third-party repository: $tp?"; then
            if add_thirdparty_repo "${still[@]}"; then
                pkgs=()
                for b in "${still[@]}"; do
                    while read -r p; do [ -n "$p" ] && pkgs+=("$p"); done < <(pkgs_for_branch "$b")
                done
                pm_upgrade "${pkgs[@]}"
                refresh_state
            fi
        else
            info "Skipped third-party repository (use --third-party to allow it)."
        fi
    fi

    # EOL branches are never moved to a newer major branch (could break apps).
    for b in "${!BRANCH_VER[@]}"; do
        if [ "${BRANCH_STATUS[$b]}" = "EOL" ]; then
            fail "PHP $b is end-of-life and still unprotected. Not switching branches automatically."
            info "Plan a migration to a supported branch (8.2+), or use a vendor-supported (ESM/LTS) PHP."
        fi
    done
}

step4_verify_and_restart() {
    title "Step 4: Verifying protection and restarting PHP services"

    # --- Verify ---
    local final=0 b
    if [ "$DRY_RUN" -eq 1 ]; then
        warn "Dry-run: verification skipped (nothing was changed)."
    elif [ "$REBOOT_NEEDED" -eq 1 ]; then
        warn "Verification deferred: the updated PHP only loads after a reboot."
    else
        refresh_state
        print_state
    fi
    for b in "${!BRANCH_VER[@]}"; do
        case "${BRANCH_STATUS[$b]}" in
            EOL)        [ $final -lt 3 ] && final=3 ;;
            VULNERABLE) final=4 ;;
        esac
    done

    # Tiny Core: the staged update is not running yet, so "vulnerable" is expected.
    if [ "$REBOOT_NEEDED" -eq 1 ] && [ $final -ne 0 ]; then final=6; fi

    if [ "$REPORT_ONLY" -eq 1 ]; then
        info "VyOS: services are not restarted in report-only mode."
        return $final
    fi

    # A reboot (not a service restart) is what activates a staged update.
    if [ "$REBOOT_NEEDED" -eq 1 ]; then
        warn "A reboot is required for the staged PHP update to take effect."
        if ask_yn "Reboot now? (never auto-approved by --yes)"; then run_cmd "Rebooting" reboot; fi
        return $final
    fi

    # --- Restart services that rely on PHP ---
    local -a active=() found=()
    local pat s dup f
    mapfile -t active < <(list_active_services)
    for pat in "${SERVICE_PATTERNS[@]}"; do
        for s in "${active[@]}"; do
            [[ $s =~ $pat ]] || continue
            dup=0; for f in "${found[@]}"; do [ "$f" = "$s" ] && dup=1; done
            [ $dup -eq 0 ] && found+=("$s")
        done
    done

    # Roundcube has no service of its own; it runs under Apache/FPM.
    if [ -d /usr/share/roundcube ] || [ -d /var/www/roundcube ] || [ -d /usr/share/webapps/roundcube ] \
       || [ -d /var/lib/roundcube ] || [ -d /usr/share/roundcubemail ]; then
        info "Roundcube detected - it runs under the web server / PHP-FPM services below."
    fi

    if [ ${#found[@]} -eq 0 ]; then
        info "No running PHP-related services were found."
        return $final
    fi

    info "Running services that rely on PHP: ${found[*]}"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] would offer to restart: ${found[*]}"
        return $final
    fi
    if [ "$ASSUME_YES" -eq 1 ] || ask_yn "Restart these services now? (brief interruption)"; then
        local failed=0
        for s in "${found[@]}"; do
            if run_cmd "Restarting $s" service_cmd restart "$s" && service_cmd is-active "$s"; then
                ok "$s restarted and running"
            else
                fail "$s did not come back up - check: journalctl -u $s (or rc-service $s status)"
                failed=1
            fi
        done
        [ $failed -eq 1 ] && ERRORS=$((ERRORS + 1))
    else
        warn "Services NOT restarted. Running processes may still use the old PHP until restarted."
    fi
    return $final
}

# =============================================================================
# Main
# =============================================================================
while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)       ASSUME_YES=1 ;;
        --third-party)  ALLOW_THIRD_PARTY=1 ;;
        --full-upgrade) FULL_UPGRADE=1 ;;
        --dry-run)      DRY_RUN=1 ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)"; exit 2 ;;
    esac
    shift
done

preflight
step1_check_installed
step2_check_vulnerable
step3_update
step4_verify_and_restart
final=$?

# --- Summary and exit code ---
echo
case $final in
    0) if [ "$ERRORS" -eq 0 ]; then ok "Done: PHP is protected against php2shell."
       else warn "PHP is protected, but $ERRORS command(s) reported errors (see $LOG_FILE)."; exit 1; fi ;;
    3) fail "Result: an end-of-life PHP branch is still unprotected. Exit code 3."; exit 3 ;;
    4) fail "Result: PHP is still VULNERABLE to php2shell. Exit code 4."; exit 4 ;;
    6) warn "Update staged: reboot, then re-run this script to verify. Exit code 6."; exit 6 ;;
esac
exit 0
