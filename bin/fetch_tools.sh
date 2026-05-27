#!/usr/bin/env bash
# Fetch external tools (currently: gitleaks) for the local or all architectures.
# Usage:
#   fetch_tools.sh [gitleaks] [--version vX.Y.Z] [--all-arch]
#
# --all-arch: download for all supported architectures (amd64 + arm64)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"
. "$LSA_ROOT/lib/arch_detect.sh"

WANT="${1:-gitleaks}"; shift || true
VERSION="v8.21.2"
ALL_ARCH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --all-arch) ALL_ARCH=1; shift;;
    *) die "unknown flag: $1";;
  esac
done

DEST="$LSA_ROOT/bin"
mkdir -p "$DEST"

fetch_gitleaks_one() {
  local arch="$1" os="$2" fname="" url=""
  case "$arch" in
    amd64) fname="gitleaks_${VERSION#v}_${os}_x64.tar.gz";;
    arm64) fname="gitleaks_${VERSION#v}_${os}_arm64.tar.gz";;
    *) log_warn "skip unsupported arch: $arch"; return 0;;
  esac
  local target="$DEST/gitleaks-${os}-${arch}"
  if [ -x "$target" ]; then
    log_info "already exists: $target"
    return 0
  fi
  url="https://github.com/gitleaks/gitleaks/releases/download/${VERSION}/${fname}"
  log_info "downloading $url"
  local tmp; tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp/$fname" || { log_warn "download failed: $arch"; rm -rf "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$tmp/$fname" || { log_warn "download failed: $arch"; rm -rf "$tmp"; return 1; }
  else
    die "neither curl nor wget present"
  fi
  tar -xzf "$tmp/$fname" -C "$tmp"
  install -m 0755 "$tmp/gitleaks" "$target"
  rm -rf "$tmp"
  log_ok "$target"
}

case "$WANT" in
  gitleaks)
    OS="$(detect_os)"
    case "$OS" in
      linux) ;;
      *) die "only Linux is supported by this fetcher";;
    esac
    if [ "$ALL_ARCH" = "1" ]; then
      for a in amd64 arm64; do
        fetch_gitleaks_one "$a" "$OS"
      done
    else
      ARCH="$(detect_arch)"
      fetch_gitleaks_one "$ARCH" "$OS"
    fi
    # symlink to current arch
    ARCH="$(detect_arch)"
    ln -sf "gitleaks-${OS}-${ARCH}" "$DEST/gitleaks"
    log_ok "symlink: $DEST/gitleaks -> gitleaks-${OS}-${ARCH}"
    ;;
  *)
    die "unknown tool: $WANT (only 'gitleaks' supported)"
    ;;
esac
