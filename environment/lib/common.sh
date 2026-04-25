#!/bin/bash
# Shared helpers for environment provisioning scripts.
# shellcheck shell=bash

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

apt_update() {
  DEBIAN_FRONTEND=noninteractive apt-get update
}

apt_update_quiet() {
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

uv_pip_install() {
  install_uv
  uv pip install --system "$@"
}

npm_install_global() {
  npm install -g "$@"
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
  local line="$1"
  touch "$HOME/.bashrc"
  if ! grep -qxF "$line" "$HOME/.bashrc"; then
    printf '%s\n' "$line" >> "$HOME/.bashrc"
  fi
}

install_uv() {
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
