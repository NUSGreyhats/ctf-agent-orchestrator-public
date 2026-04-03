#!/bin/bash
# Install custom tools for agent collaboration.
# The notify_teammates tool is provided via SDK for Claude/Codex/Copilot
# and via a TypeScript tool file for OpenCode.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/../hooks/opencode_tools"

echo "--- Installing collaboration tools ---"

# OpenCode: copy notify_teammates tool to global tools directory
OPENCODE_TOOLS_DIR="$HOME/.config/opencode/tools"
if command -v opencode &>/dev/null; then
    mkdir -p "$OPENCODE_TOOLS_DIR"
    if [ -f "$TOOLS_DIR/notify_teammates.ts" ]; then
        cp "$TOOLS_DIR/notify_teammates.ts" "$OPENCODE_TOOLS_DIR/"
        echo "  OpenCode: notify_teammates tool installed"
    fi
else
    echo "  OpenCode: not installed, skipping"
fi

# Claude, Codex, Copilot: notify_teammates is registered via SDK
# at runtime (no installation step needed)
echo "  Claude/Codex/Copilot: tools registered via SDK at runtime"

echo "--- Collaboration tools installed ---"
