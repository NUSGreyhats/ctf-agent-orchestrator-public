#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

curl -fsSL https://claude.ai/install.sh | bash

~/.local/bin/claude plugin marketplace add trailofbits/skills || true
~/.local/bin/claude plugin marketplace add trailofbits/skills-curated || true

# Skills are installed by 013_install-skills.sh.

# Install GDB MCP server dependency.
uv_pip_install --reinstall 'mcp[cli]'

# Register MCP servers via claude mcp add (stores in ~/.claude.json).
~/.local/bin/claude mcp add --transport stdio --scope user gdb -- python3 /root/ctf-agent-wrapper/mcps/gdb_mcp.py || true
~/.local/bin/claude mcp add --transport stdio --scope user ida -e IDADIR=/opt/ida-pro-9.3 -- ida-mcp || true

append_bashrc_line "alias yolo='IS_SANDBOX=1 claude --dangerously-skip-permissions'"
