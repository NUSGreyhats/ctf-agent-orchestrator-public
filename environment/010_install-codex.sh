#!/bin/bash

set -euo pipefail
set -x

npm install -g @openai/codex@latest

# Register local MCP servers for Codex.
codex mcp remove gdb || true
codex mcp add gdb -- python3 /root/ctf-agent-wrapper/mcps/gdb_mcp.py
codex mcp remove ida || true
IDADIR=/opt/ida-pro-9.3 codex mcp add ida -- ida-mcp
codex mcp list
