#!/bin/bash
# Install custom runtime tools for agent collaboration.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

log "Installing collaboration tools"
log "Claude and Codex collaboration tools are registered via SDK at runtime"
