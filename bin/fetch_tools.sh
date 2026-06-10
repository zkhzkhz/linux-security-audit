#!/usr/bin/env bash
# Fetch external tools for the local or all architectures.
# Usage:
#   fetch_tools.sh [tool] [--version vX.Y.Z] [--all-arch]
#   Supported tools: gitleaks, trivy, amicontained
#   --all-arch: download for all supported architectures (amd64 + arm64)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"
. "$LSA_ROOT/lib/arch_detect.sh"

WANT="${1:-all}"; shift || true
VERSION=""
ALL_ARCH=0
TIMEOUT_SEC=60

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --all-arch) ALL_ARCH=1; shift;;
    *) die "unknown flag: $1";;
  esac
done

DEST="$LSA_ROOT/bin"
mkdir -p "$DEST"

# Helper: download with timeout, skip on failure
download_with_timeout() {
  local url="$1" output="$2"
  log_info "downloading $url (timeout: ${TIMEOUT_SEC}s)"
  if command -v timeout >/dev/null 2>&1; then
    if timeout "$TIMEOUT_SEC" curl -fsSL "$url" -o "$output" 2>/dev/null; then
      return 0
    fi
  elif command -v curl >/dev/null 2>&1; then
    if curl -fsSL --connect-timeout 10 -m "$TIMEOUT_SEC" "$url" -o "$output" 2>/dev/null; then
      return 0
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q --timeout="$TIMEOUT_SEC" "$url" -O "$output" 2>/dev/null; then
      return 0
    fi
  else
    log_warn "neither curl nor wget present"
    return 1
  fi
  log_warn "download failed or timed out: $url"
  return 1
}

fetch_gitleaks_one() {
  local arch="$1" os="$2"
  local VERSION="${VERSION:-v8.21.2}"
  local fname="" url=""
  case "$arch" in
    amd64) fname="gitleaks_${VERSION#v}_${os}_x64.tar.gz";;
    arm64) fname="gitleaks_${VERSION#v}_${os}_arm64.tar.gz";;
    *) log_warn "skip unsupported arch: $arch"; return 0;;
  esac
  local target="$DEST/gitleaks-${os}-${arch}"
  local gz_target="$DEST/gitleaks-${os}-${arch}.gz"

  # Check if compressed version exists and decompress
  if [ -f "$gz_target" ] && [ ! -x "$target" ]; then
    log_info "decompressing $gz_target..."
    (cd "$DEST" && gunzip -k "gitleaks-${os}-${arch}.gz" && chmod +x "gitleaks-${os}-${arch}")
    if [ -x "$target" ]; then
      log_ok "decompressed: $target"
      return 0
    fi
  fi

  if [ -x "$target" ]; then
    log_info "already exists: $target"
    return 0
  fi
  url="https://github.com/gitleaks/gitleaks/releases/download/${VERSION}/${fname}"
  local tmp; tmp="$(mktemp -d)"
  if download_with_timeout "$url" "$tmp/$fname"; then
    tar -xzf "$tmp/$fname" -C "$tmp" 2>/dev/null
    install -m 0755 "$tmp/gitleaks" "$target" 2>/dev/null
    log_ok "$target"
  fi
  rm -rf "$tmp"
}

fetch_trivy_one() {
  local arch="$1" os="$2"
  local TRIVY_VER="${VERSION:-v0.71.0}"
  TRIVY_VER="${TRIVY_VER#v}"
  local target="$DEST/trivy-${os}-${arch}"
  local gz_target="$DEST/trivy-${os}-${arch}.gz"

  # Check if compressed version exists and decompress
  if [ -f "$gz_target" ] && [ ! -x "$target" ]; then
    log_info "decompressing $gz_target..."
    (cd "$DEST" && gunzip -k "trivy-${os}-${arch}.gz" && chmod +x "trivy-${os}-${arch}")
    if [ -x "$target" ]; then
      log_ok "decompressed: $target"
      return 0
    fi
  fi

  if [ -x "$target" ]; then
    log_info "already exists: $target"
    return 0
  fi
  local suffix=""
  case "$os" in
    linux)
      case "$arch" in
        amd64) suffix="Linux-64bit";;
        arm64) suffix="Linux-ARM64";;
        *) log_warn "skip unsupported arch: $arch"; return 0;;
      esac
      ;;
    windows)
      case "$arch" in
        amd64) suffix="Windows-64bit";;
        *) log_warn "skip unsupported arch for windows: $arch"; return 0;;
      esac
      target="$DEST/trivy-${os}-${arch}.exe"
      gz_target="$DEST/trivy-${os}-${arch}.exe.gz"
      ;;
    *)
      log_warn "skip unsupported os: $os"; return 0;;
  esac
  local url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_${suffix}.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  if download_with_timeout "$url" "$tmp/trivy.tar.gz"; then
    tar xzf "$tmp/trivy.tar.gz" -C "$tmp" trivy 2>/dev/null && \
    install -m 0755 "$tmp/trivy" "$target" 2>/dev/null && \
    log_ok "$target"
  fi
  rm -rf "$tmp"
}

fetch_amicontained_one() {
  local arch="$1" os="$2"
  local AMICONTAINED_VER="${VERSION:-v0.4.9}"
  local target="$DEST/amicontained-${os}-${arch}"
  if [ -x "$target" ]; then
    log_info "already exists: $target"
    return 0
  fi
  local arch_name=""
  case "$arch" in
    amd64) arch_name="amd64";;
    arm64) arch_name="arm64";;
    *) log_warn "skip unsupported arch: $arch"; return 0;;
  esac
  local url="https://github.com/genuinetools/amicontained/releases/download/${AMICONTAINED_VER}/amicontained-${os}-${arch_name}"
  local tmp; tmp="$(mktemp -d)"
  if download_with_timeout "$url" "$tmp/amicontained"; then
    install -m 0755 "$tmp/amicontained" "$target" 2>/dev/null
    log_ok "$target"
  fi
  rm -rf "$tmp"
}

# Detect OS
OS="$(detect_os)"
case "$OS" in
  linux) ;;
  *) die "only Linux is supported by this fetcher";;
esac

# Determine architectures to fetch
if [ "$ALL_ARCH" = "1" ]; then
  ARCHS="amd64 arm64"
else
  ARCHS="$(detect_arch)"
fi

fetch_tool() {
  local tool="$1"
  case "$tool" in
    gitleaks)
      for a in $ARCHS; do fetch_gitleaks_one "$a" "$OS"; done
      ;;
    trivy)
      for a in $ARCHS; do fetch_trivy_one "$a" "$OS"; done
      ;;
    amicontained)
      for a in $ARCHS; do fetch_amicontained_one "$a" "$OS"; done
      ;;
    *) die "unknown tool: $tool";;
  esac
}

# Create symlinks for current arch
create_symlinks() {
  local ARCH="$(detect_arch)"
  for tool in gitleaks trivy amicontained; do
    local target="$DEST/${tool}-${OS}-${ARCH}"
    if [ -x "$target" ]; then
      ln -sf "${tool}-${OS}-${ARCH}" "$DEST/$tool"
      log_ok "symlink: $DEST/$tool -> ${tool}-${OS}-${ARCH}"
    fi
  done
}

case "$WANT" in
  all)
    for tool in gitleaks trivy amicontained; do
      log_info "fetching $tool..."
      fetch_tool "$tool"
    done
    ;;
  gitleaks|trivy|amicontained)
    fetch_tool "$WANT"
    ;;
  *)
    die "unknown tool: $WANT (supported: gitleaks, trivy, amicontained, all)"
    ;;
esac

create_symlinks
log_ok "done"
