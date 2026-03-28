#!/bin/bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

curl -fsSL https://claude.ai/install.sh | bash

~/.local/bin/claude plugin marketplace add trailofbits/skills
~/.local/bin/claude plugin marketplace add trailofbits/skills-curated

wget https://github.com/trailofbits/claude-code-config/raw/main/claude-md-template.md -O ~/.claude/CLAUDE.md

mkdir -p ~/.claude/skills
cp -r "$SCRIPT_DIR/../skills/"* ~/.claude/skills/

# Install ljagiello/ctf-skills (exclude solve-challenge and ctf-forensics)
git clone --depth 1 https://github.com/ljagiello/ctf-skills.git /tmp/ljagiello-ctf-skills
for d in /tmp/ljagiello-ctf-skills/*/; do
    name="$(basename "$d")"
    case "$name" in
        solve-challenge|ctf-forensics|ctf-writeup|scripts|tests|.github) continue ;;
    esac
    [ -d "$d" ] && cp -r "$d" ~/.claude/skills/
done
rm -rf /tmp/ljagiello-ctf-skills

# Install GDB MCP server dependency
python3 -m pip install --break-system-packages --ignore-installed 'mcp[cli]'

# Register GDB MCP server in Claude Code settings
python3 - <<'EOF'
import json
from pathlib import Path

settings_path = Path.home() / ".claude" / "settings.json"
settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
settings.setdefault("mcpServers", {})["gdb"] = {
    "command": "python3",
    "args": ["/root/all-things-ai/mcps/gdb_mcp.py"],
}
settings_path.write_text(json.dumps(settings, indent=2) + "\n")
EOF

echo "alias yolo='IS_SANDBOX=1 claude --dangerously-skip-permissions'" >> ~/.bashrc
