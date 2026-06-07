#!/bin/bash
# Validate that the provisioned CTF workstation has critical tools installed.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
APP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

failures=0
failure_messages=()
VALIDATE_TIMEOUT_SECONDS="${VALIDATE_TIMEOUT_SECONDS:-60}"

record_failure() {
  local msg="$1"
  warn "$msg"
  failure_messages+=("$msg")
  failures=$((failures + 1))
}

with_validation_timeout() {
  timeout "${VALIDATE_TIMEOUT_SECONDS}s" "$@"
}

check_cmd() {
  local name="$1"
  shift || true
  if have_cmd "$name"; then
    if [ "$#" -gt 0 ]; then
      with_validation_timeout "$@" >/dev/null 2>&1 || warn "$name exists but validation command failed or timed out after ${VALIDATE_TIMEOUT_SECONDS}s: $*"
    fi
    log "OK command: $name"
  else
    record_failure "Missing command: $name"
  fi
}

check_path() {
  local path="$1"
  if [ -e "$path" ]; then
    log "OK path: $path"
  else
    record_failure "Missing path: $path"
  fi
}

check_py_import() {
  local module="$1"
  if with_validation_timeout python3 -c "import ${module}" >/dev/null 2>&1; then
    log "OK python import: $module"
  else
    record_failure "Missing python import: $module"
  fi
}

check_cmd python3 python3 --version
check_cmd node node --version
check_cmd npm npm --version
check_cmd uv uv --version
check_cmd gdb gdb --version
check_cmd rg rg --version
check_cmd ctfgrep ctfgrep -h
check_cmd docker docker --version

check_cmd claude claude --version
check_cmd codex codex --version
check_path "$APP_ROOT/all-skills/ctf-methodology/SKILL.md"

check_cmd apktool apktool --version
check_cmd jadx jadx --version
check_cmd sage sage --version
check_cmd mquire mquire --version
check_cmd bulk_extractor bulk_extractor -h
check_cmd tshark tshark --version
check_cmd vol vol --help

check_py_import starlette
check_py_import uvicorn
check_py_import multipart
check_py_import itsdangerous
check_py_import httpx
check_py_import requests
check_py_import websockets
check_py_import claude_agent_sdk
check_py_import mcp.server.fastmcp
check_py_import idapro
check_py_import ida_domain
check_py_import pwn
check_py_import angr
check_py_import volatility3
check_py_import scapy
check_py_import pytsk3
check_py_import oletools

if [ "$failures" -ne 0 ]; then
  warn "Environment validation failed with $failures missing requirement(s):"
  for msg in "${failure_messages[@]}"; do
    warn "  - $msg"
  done
  exit 1
fi

log "Environment validation completed successfully."
