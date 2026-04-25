#!/bin/bash
# Validate that the provisioned CTF workstation has critical tools installed.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

failures=0

check_cmd() {
  local name="$1"
  shift || true
  if have_cmd "$name"; then
    if [ "$#" -gt 0 ]; then
      "$@" >/dev/null 2>&1 || warn "$name exists but validation command failed: $*"
    fi
    log "OK command: $name"
  else
    warn "Missing command: $name"
    failures=$((failures + 1))
  fi
}

check_path() {
  local path="$1"
  if [ -e "$path" ]; then
    log "OK path: $path"
  else
    warn "Missing path: $path"
    failures=$((failures + 1))
  fi
}

check_py_import() {
  local module="$1"
  if python3 -c "import ${module}" >/dev/null 2>&1; then
    log "OK python import: $module"
  else
    warn "Missing python import: $module"
    failures=$((failures + 1))
  fi
}

check_cmd python3 python3 --version
check_cmd node node --version
check_cmd npm npm --version
check_cmd uv uv --version
check_cmd gdb gdb --version
check_cmd rg rg --version
check_cmd ctfgrep ctfgrep --help
check_cmd docker docker --version

check_cmd claude claude --version
check_cmd codex codex --version
check_cmd copilot copilot --version
check_cmd opencode opencode --version

check_cmd ida-mcp ida-mcp --help
check_cmd ida-mcp-bin ida-mcp-bin --help
check_cmd apktool apktool --version
check_cmd jadx jadx --version
check_cmd sage sage --version
check_cmd mquire mquire --version
check_cmd bulk_extractor bulk_extractor -h
check_cmd tshark tshark --version
check_cmd vol vol --help

check_py_import starlette
check_py_import uvicorn
check_py_import httpx
check_py_import websockets
check_py_import claude_agent_sdk
check_py_import copilot
check_py_import opencode_sdk
check_py_import mcp.server.fastmcp
check_py_import pwn
check_py_import angr
check_py_import volatility3
check_py_import scapy
check_py_import pytsk3
check_py_import oletools
check_py_import libdebug

if [ "$failures" -ne 0 ]; then
  warn "Environment validation failed with $failures missing requirement(s)."
  exit 1
fi

log "Environment validation completed successfully."
