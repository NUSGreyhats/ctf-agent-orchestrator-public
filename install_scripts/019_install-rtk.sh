#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Install RTK, a Rust CLI proxy for compact command output.
if ! have_cmd cargo; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck source=/dev/null
source "$HOME/.cargo/env"

while read -r name source; do
  if [ -z "$name" ] || [[ "$name" == \#* ]]; then
    continue
  fi
  if ! have_cmd "$name"; then
    with_lock cargo cargo install --git "$source"
  fi
done < "$SCRIPT_DIR/requirements-cargo.txt"
