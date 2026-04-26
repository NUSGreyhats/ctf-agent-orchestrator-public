#!/bin/bash
# Shared helpers for environment provisioning scripts.
# shellcheck shell=bash

LOCK_ROOT="${CTF_AGENT_LOCK_ROOT:-/var/lock/ctf-agent-wrapper}"

# Non-interactive provisioning shells do not read ~/.bashrc, so expose tools
# installed outside the default system PATH to every setup/validation script.
export PATH="$HOME/.local/bin:/opt/ida-pro-9.3:/opt/jadx-1.5.5/bin:$PATH"

log() {
  printf '==> %s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

retry() {
  local attempts="$1"
  shift
  local n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      return 1
    fi
    sleep $((n * 2))
    n=$((n + 1))
  done
}

with_lock() {
  local lock_name="$1"
  shift
  mkdir -p "$LOCK_ROOT"
  local lock_file="$LOCK_ROOT/${lock_name}.lock"
  (
    flock -x 200
    "$@"
  ) 200>"$lock_file"
}

apt_update() {
  with_lock apt env DEBIAN_FRONTEND=noninteractive apt-get update
}

apt_update_quiet() {
  with_lock apt env DEBIAN_FRONTEND=noninteractive apt-get update -qq
}

apt_install() {
  with_lock apt env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

apt_remove() {
  with_lock apt env DEBIAN_FRONTEND=noninteractive apt-get remove -y "$@"
}

pip_install() {
  with_lock python python3 -m pip install "$@"
}

uv_pip_install() {
  install_uv
  with_lock python uv pip install --system --break-system-packages "$@"
}

uv_tool_install() {
  install_uv
  with_lock uv-tools uv tool install "$@"
}

npm_install_global() {
  with_lock npm npm install -g "$@"
}

npm_uninstall_global() {
  with_lock npm npm uninstall -g "$@"
}

gem_install() {
  with_lock gem gem install "$@"
}

download_file() {
  local url="$1"
  local dest="$2"
  if [ -f "$dest" ]; then
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  local tmp
  tmp="${dest}.tmp.$$"
  rm -f "$tmp"
  retry 3 curl -fsSL "$url" -o "$tmp"
  mv "$tmp" "$dest"
}

append_bashrc_line() {
  with_lock bashrc _append_bashrc_line_unlocked "$@"
}

_append_bashrc_line_unlocked() {
  local line="$1"
  touch "$HOME/.bashrc"
  if ! grep -qxF "$line" "$HOME/.bashrc"; then
    printf '%s\n' "$line" >> "$HOME/.bashrc"
  fi
}

install_uv() {
  export PATH="$HOME/.local/bin:$PATH"
  if have_cmd uv; then
    return 0
  fi
  with_lock uv-bootstrap _install_uv_unlocked
  export PATH="$HOME/.local/bin:$PATH"
}

_install_uv_unlocked() {
  if have_cmd uv; then
    return 0
  fi
  local installer
  installer="$(mktemp)"
  retry 3 curl -LsSf https://astral.sh/uv/install.sh -o "$installer"
  sh "$installer"
  rm -f "$installer"
  export PATH="$HOME/.local/bin:$PATH"
}
