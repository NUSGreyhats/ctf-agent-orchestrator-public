#!/bin/bash
# Install custom runtime tools for agent collaboration.
#
# Claude, Codex, and Copilot register notify_teammates dynamically via
# their SDK integrations. OpenCode still needs a TypeScript tool file in
# ~/.config/opencode/tools so it can write broadcasts to _shared/.notify_queue.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

TOOLS_DIR="$SCRIPT_DIR/../hooks/opencode_tools"
OPENCODE_TOOLS_DIR="$HOME/.config/opencode/tools"

log "Installing collaboration tools"

if have_cmd opencode; then
  mkdir -p "$OPENCODE_TOOLS_DIR"
  if [ -f "$TOOLS_DIR/notify_teammates.ts" ]; then
    cp "$TOOLS_DIR/notify_teammates.ts" "$OPENCODE_TOOLS_DIR/"
    log "OpenCode notify_teammates tool installed"
  else
    warn "OpenCode notify_teammates tool not found at $TOOLS_DIR"
  fi
else
  warn "OpenCode is not installed; skipping OpenCode tool install"
fi

log "Claude/Codex/Copilot collaboration tools are registered via SDK at runtime"
