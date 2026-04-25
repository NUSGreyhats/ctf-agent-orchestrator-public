#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# GitHub Copilot CLI: pin version and patch interaction headers to agent mode
#

COPILOT_VERSION="0.0.421"

npm uninstall -g @github/copilot || true
npm_install_global "@github/copilot@${COPILOT_VERSION}"
copilot --version

COPILOT_NPM_ROOT="$(npm root -g)"
COPILOT_MODULE_DIR="${COPILOT_NPM_ROOT}/@github/copilot"
COPILOT_INDEX="${COPILOT_MODULE_DIR}/index.js"
COPILOT_SDK="${COPILOT_MODULE_DIR}/sdk/index.js"

# Backward compatibility for older Copilot layouts that unpack into ~/.copilot/pkg.
if [[ ! -f "$COPILOT_INDEX" || ! -f "$COPILOT_SDK" ]]; then
  COPILOT_INDEX="$(find "$HOME/.copilot/pkg" -type f -path '*/index.js' ! -path '*/sdk/*' 2>/dev/null | head -n1 || true)"
  COPILOT_SDK="$(find "$HOME/.copilot/pkg" -type f -path '*/sdk/index.js' 2>/dev/null | head -n1 || true)"
fi

if [[ -z "${COPILOT_INDEX:-}" || -z "${COPILOT_SDK:-}" || ! -f "$COPILOT_INDEX" || ! -f "$COPILOT_SDK" ]]; then
  echo "Could not locate Copilot patch targets (index.js/sdk/index.js)." >&2
  exit 1
fi

sed -i 's/conversation-user/conversation-agent/' "$COPILOT_INDEX"
sed -i 's/conversation-user/conversation-agent/' "$COPILOT_SDK"
sed -i 's/r\["X-Interaction-Type"\]=this.requestContext.interactionType/r["X-Interaction-Type"]="conversation-agent"/' "$COPILOT_INDEX"
sed -i 's/r\["X-Interaction-Type"\]=this.requestContext.interactionType/r["X-Interaction-Type"]="conversation-agent"/' "$COPILOT_SDK"
sed -i 's/X-Initiator":"user"/X-Initiator":"agent"/' "$COPILOT_INDEX"
sed -i 's/X-Initiator":"user"/X-Initiator":"agent"/' "$COPILOT_SDK"
sed -i 's/\["X-Initiator"\]="user"/["X-Initiator"]="agent"/' "$COPILOT_INDEX"
sed -i 's/\["X-Initiator"\]="user"/["X-Initiator"]="agent"/' "$COPILOT_SDK"
