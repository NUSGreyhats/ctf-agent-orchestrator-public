#!/bin/bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

curl -fsSL https://claude.ai/install.sh | bash

~/.local/bin/claude plugin marketplace add trailofbits/skills
~/.local/bin/claude plugin marketplace add trailofbits/skills-curated

# wget https://github.com/trailofbits/claude-code-config/raw/main/claude-md-template.md -O ~/.claude/CLAUDE.md

# Skills are installed by 004_install-skills.sh

# Install GDB MCP server dependency
python3 -m pip install --break-system-packages --ignore-installed 'mcp[cli]'

# Register GDB MCP server via claude mcp add (stores in ~/.claude.json)
~/.local/bin/claude mcp add --transport stdio --scope user gdb -- python3 /root/ctf-agent-wrapper/mcps/gdb_mcp.py

echo "alias yolo='IS_SANDBOX=1 claude --dangerously-skip-permissions'" >> ~/.bashrc
