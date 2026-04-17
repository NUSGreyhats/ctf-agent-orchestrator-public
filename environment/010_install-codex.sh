#!/bin/bash

set -euo pipefail
set -x

npm install -g @openai/codex@latest

# Register local GDB MCP server for Codex.
codex mcp remove gdb || true
codex mcp add gdb -- python3 /root/ctf-agent-wrapper/mcps/gdb_mcp.py
codex mcp list
