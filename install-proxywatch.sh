#!/usr/bin/env bash
#
# install-proxywatch.sh
# Made using Claude AI Sonnet 5.5 Medium. Still needs testing.
# All credit goes to In3x0rabl3. This script is just to fix some errors I ran into.
# -----------------------------------------------------------------------------
# What this script does:
#   1. Detects the distro (Ubuntu, Debian, Fedora, Rocky Linux; also RHEL/Alma)
#      and installs the build prerequisites (git, make, curl, tar, gzip,
#      ca-certificates) using apt or dnf.
#   2. Clones (or updates) https://github.com/In3x0rabl3/Proxywatch.
#   3. Reads the Go version the project requires from proxywatch/go.mod
#      (the "toolchain" line, falling back to the "go" line) and installs
#      exactly that Go version from go.dev into /usr/local/go. Distro Go
#      packages are too old for this project, which is what causes the
#      "make" build errors. Existing matching installs are reused.
#   4. Builds ONLY the native Linux binary (the stock Makefile tries to
#      cross-compile Windows/macOS/arm targets too, which is slow and can fail).
#   5. Symlinks the binary to /usr/local/bin/proxywatch.
#   6. Does NOT start Proxywatch. It prints sample commands when finished.
#
# Usage:   sudo ./install-proxywatch.sh
# Options (environment variables):
#   INSTALL_DIR=/opt/Proxywatch   where the repo is cloned
#   GO_VERSION=1.25.8             override the Go version (default: from go.mod)
# -----------------------------------------------------------------------------

set -euo pipefail

REPO_URL="https://github.com/In3x0rabl3/Proxywatch.git"
INSTALL_DIR="${INSTALL_DIR:-/opt/Proxywatch}"
GO_ROOT="/usr/local/go"
FALLBACK_GO_VERSION="1.25.8"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Root check ---------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  die "Run as root, e.g.: sudo $0"
fi

# --- Detect distro / package manager -----------------------------------------
[[ -r /etc/os-release ]] || die "Cannot read /etc/os-release; unsupported system."
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_IDS=" ${ID:-} ${ID_LIKE:-} "

if [[ $DISTRO_IDS == *" debian "* || $DISTRO_IDS == *" ubuntu "* ]]; then
  PKG_MGR="apt"
elif [[ $DISTRO_IDS == *" fedora "* || $DISTRO_IDS == *" rhel "* || $DISTRO_IDS == *" centos "* || $DISTRO_IDS == *" rocky "* ]]; then
  PKG_MGR="dnf"
else
  die "Unsupported distro: ${PRETTY_NAME:-unknown}. Supported: Ubuntu, Debian, Fedora, Rocky Linux."
fi
log "Detected ${PRETTY_NAME:-$ID} (package manager: $PKG_MGR)"

# --- Architecture -------------------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64)  GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) die "Unsupported CPU architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
esac

# --- Install prerequisite packages -------------------------------------------
log "Installing prerequisites (git, make, curl, tar, gzip, ca-certificates)..."
if [[ $PKG_MGR == "apt" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends git make curl tar gzip ca-certificates
else
  # Only install what's missing; avoids curl vs curl-minimal conflicts on Rocky/RHEL.
  need=()
  for pair in git:git make:make curl:curl tar:tar gzip:gzip; do
    cmd="${pair%%:*}"; pkg="${pair##*:}"
    command -v "$cmd" >/dev/null 2>&1 || need+=("$pkg")
  done
  need+=("ca-certificates")
  dnf install -y "${need[@]}"
fi

# --- Clone or update the repo -------------------------------------------------
if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Repo already present at $INSTALL_DIR; updating..."
  git -C "$INSTALL_DIR" fetch --depth 1 origin
  git -C "$INSTALL_DIR" reset --hard origin/HEAD
else
  log "Cloning $REPO_URL into $INSTALL_DIR..."
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi

BUILD_DIR="$INSTALL_DIR/proxywatch"
[[ -f "$BUILD_DIR/go.mod" ]] || die "Expected $BUILD_DIR/go.mod not found; repo layout may have changed."

# --- Work out which Go version is required -----------------------------------
if [[ -n "${GO_VERSION:-}" ]]; then
  :
else
  GO_VERSION="$(awk '$1=="toolchain" {sub(/^go/,"",$2); print $2; exit}' "$BUILD_DIR/go.mod")"
  if [[ -z "$GO_VERSION" ]]; then
    GO_VERSION="$(awk '$1=="go" {print $2; exit}' "$BUILD_DIR/go.mod")"
  fi
  GO_VERSION="${GO_VERSION:-$FALLBACK_GO_VERSION}"
fi
log "Required Go version: $GO_VERSION"

# --- Install Go from go.dev (distro packages are too old) --------------------
installed_go=""
if [[ -x "$GO_ROOT/bin/go" ]]; then
  installed_go="$("$GO_ROOT/bin/go" env GOVERSION 2>/dev/null | sed 's/^go//' || true)"
fi

if [[ "$installed_go" == "$GO_VERSION" ]]; then
  log "Go $GO_VERSION already installed at $GO_ROOT; skipping."
else
  tarball="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  log "Downloading $tarball ..."
  curl -fsSL -o "$tmp/$tarball" "https://go.dev/dl/$tarball" \
    || die "Failed to download Go $GO_VERSION from go.dev."

  log "Verifying checksum..."
  expected="$(curl -fsSL "https://go.dev/dl/$tarball.sha256" | tr -d '[:space:]' || true)"
  [[ -n "$expected" ]] || die "Could not fetch the SHA-256 checksum for $tarball."
  actual="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
  [[ "$expected" == "$actual" ]] || die "Checksum mismatch for $tarball (expected $expected, got $actual)."

  log "Installing Go $GO_VERSION to $GO_ROOT ..."
  rm -rf "$GO_ROOT"
  tar -C /usr/local -xzf "$tmp/$tarball"
fi

# Make Go available in future login shells.
cat > /etc/profile.d/go.sh <<'PROFILE'
export PATH="$PATH:/usr/local/go/bin"
PROFILE
chmod 644 /etc/profile.d/go.sh

# Use this Go for the build and never let it try to fetch a different toolchain.
export PATH="$GO_ROOT/bin:$PATH"
export GOTOOLCHAIN=local
log "Using $(go version)"

# --- Build (native Linux target only) ----------------------------------------
log "Building Proxywatch for linux/$GOARCH ..."
cd "$BUILD_DIR"
make clean
make TARGETS="linux/$GOARCH"

BIN="$BUILD_DIR/build/proxywatch-linux-${GOARCH}"
[[ -x "$BIN" ]] || die "Build finished but $BIN was not found."

ln -sf "$BIN" /usr/local/bin/proxywatch

# --- Done (intentionally NOT starting the service) ---------------------------
cat <<MSG

==============================================================================
 Proxywatch components are installed. Nothing has been started.
==============================================================================
 Binary:  $BIN
 Symlink: /usr/local/bin/proxywatch
 Go:      $(go version)

 Sample commands (run as root; open a new shell or run
 'source /etc/profile.d/go.sh' if you need 'go' on your PATH):

   # Standalone mode with local TUI dashboard
   sudo proxywatch

   # Server mode: accept agent connections
   sudo proxywatch -listen 0.0.0.0:50051

   # Agent mode: stream telemetry to a server
   sudo proxywatch -connect 10.0.0.5:50051 -id WS01

   # Server/agent with a shared auth token
   sudo proxywatch -listen 0.0.0.0:50051 -agent-token 'CHANGE_ME'
   sudo proxywatch -connect 10.0.0.5:50051 -id WS01 -agent-token 'CHANGE_ME'

   # Headless contour probe server / client
   sudo proxywatch -contour-server -contour-proto https -contour-ports 443
   proxywatch -contour-client 10.0.0.5 -contour-proto https

 Note: if you use server mode, open TCP 50051 in your firewall as needed
 (ufw allow 50051/tcp  |  firewall-cmd --add-port=50051/tcp --permanent).
==============================================================================
MSG
