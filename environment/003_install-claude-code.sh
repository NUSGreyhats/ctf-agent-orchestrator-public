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

echo "alias yolo='IS_SANDBOX=1 claude --dangerously-skip-permissions'" >> ~/.bashrc
