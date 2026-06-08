#!/usr/bin/env bash
# Arch + OS detection. Source after common.sh.

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64)        echo "amd64";;
    aarch64|arm64)       echo "arm64";;
    armv7l|armv6l)       echo "arm";;
    *)                   echo "$m";;
  esac
}

detect_os() {
  case "$(uname -s)" in
    Linux)  echo "linux";;
    Darwin) echo "darwin";;
    MINGW*|MSYS*|CYGWIN*) echo "windows";;
    *)      echo "unknown";;
  esac
}

is_windows() {
  [ "$(detect_os)" = "windows" ]
}

is_linux() {
  [ "$(detect_os)" = "linux" ]
}

# Pick a gitleaks binary: prefer LSA bundled binary, then $PATH.
pick_gitleaks() {
  local arch os
  arch="$(detect_arch)"; os="$(detect_os)"

  # Windows path
  if [ "$os" = "windows" ]; then
    local cand="$LSA_ROOT/bin/windows/gitleaks.exe"
    if [ -x "$cand" ]; then echo "$cand"; return 0; fi
  fi

  # Linux/macOS path
  local cand="$LSA_ROOT/bin/gitleaks-${os}-${arch}"
  if [ -x "$cand" ]; then echo "$cand"; return 0; fi
  if command -v gitleaks >/dev/null 2>&1; then command -v gitleaks; return 0; fi
  return 1
}

pick_nmap() {
  command -v nmap 2>/dev/null
}

# Windows-specific tool paths
pick_winpeas() {
  local cand="$LSA_ROOT/bin/windows/winpeas.exe"
  [ -f "$cand" ] && echo "$cand" && return 0
  return 1
}

pick_seatbelt() {
  local cand="$LSA_ROOT/bin/windows/seatbelt.exe"
  [ -f "$cand" ] && echo "$cand" && return 0
  return 1
}

pick_sharpup() {
  local cand="$LSA_ROOT/bin/windows/sharpup.exe"
  [ -f "$cand" ] && echo "$cand" && return 0
  return 1
}

pick_watson() {
  local cand="$LSA_ROOT/bin/windows/watson.exe"
  [ -f "$cand" ] && echo "$cand" && return 0
  return 1
}
