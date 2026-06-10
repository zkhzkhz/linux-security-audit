#!/usr/bin/env bash
# Pre-bundle all tools for all platforms
# Run this during build/release to include binaries in the repo
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

DEST="$LSA_ROOT/bin"
mkdir -p "$DEST"

TIMEOUT_SEC=120

download_with_timeout() {
  local url="$1" output="$2"
  log_info "downloading $url"
  if command -v wget >/dev/null 2>&1; then
    wget -q --timeout="$TIMEOUT_SEC" "$url" -O "$output"
  else
    curl -fsSL --connect-timeout 10 -m "$TIMEOUT_SEC" "$url" -o "$output"
  fi
}

# Trivy v0.71.0
fetch_trivy() {
  local VER="0.71.0"
  local platforms=(
    "Linux-64bit:trivy-linux-amd64"
    "Linux-ARM64:trivy-linux-arm64"
    "Windows-64bit:trivy-windows-amd64.exe"
  )
  for p in "${platforms[@]}"; do
    local suffix="${p%:*}"
    local target="${p#*:}"
    local url="https://github.com/aquasecurity/trivy/releases/download/v${VER}/trivy_${VER}_${suffix}.tar.gz"
    if [ -x "$DEST/$target" ]; then
      log_info "exists: $DEST/$target"
      continue
    fi
    local tmp; tmp="$(mktemp -d)"
    if download_with_timeout "$url" "$tmp/trivy.tar.gz"; then
      tar xzf "$tmp/trivy.tar.gz" -C "$tmp" trivy 2>/dev/null
      mv "$tmp/trivy" "$DEST/$target"
      chmod +x "$DEST/$target"
      log_ok "$DEST/$target"
    fi
    rm -rf "$tmp"
  done
}

# Gitleaks v8.21.2
fetch_gitleaks() {
  local VER="8.21.2"
  local platforms=(
    "linux_x64:gitleaks-linux-amd64"
    "linux_arm64:gitleaks-linux-arm64"
    "windows_x64.exe:gitleaks-windows-amd64.exe"
  )
  for p in "${platforms[@]}"; do
    local suffix="${p%:*}"
    local target="${p#*:}"
    local url="https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_${suffix}.tar.gz"
    if [ -x "$DEST/$target" ]; then
      log_info "exists: $DEST/$target"
      continue
    fi
    local tmp; tmp="$(mktemp -d)"
    if download_with_timeout "$url" "$tmp/gitleaks.tar.gz"; then
      tar xzf "$tmp/gitleaks.tar.gz" -C "$tmp" gitleaks 2>/dev/null
      mv "$tmp/gitleaks" "$DEST/$target"
      chmod +x "$DEST/$target"
      log_ok "$DEST/$target"
    fi
    rm -rf "$tmp"
  done
}

# Linux Exploit Suggester
fetch_les() {
  local target="$DEST/linux-exploit-suggester.sh"
  if [ -x "$target" ]; then
    log_info "exists: $target"
    return
  fi
  download_with_timeout "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "$target"
  chmod +x "$target"
  log_ok "$target"
}

log_info "Fetching Trivy v0.71.0..."
fetch_trivy

log_info "Fetching Gitleaks v8.21.2..."
fetch_gitleaks

log_info "Fetching Linux Exploit Suggester..."
fetch_les

log_ok "All tools pre-bundled"
ls -la "$DEST"/*.{sh,exe} "$DEST"/trivy-* "$DEST"/gitleaks-* 2>/dev/null || ls -la "$DEST"
