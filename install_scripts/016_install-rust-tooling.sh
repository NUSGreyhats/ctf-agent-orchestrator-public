#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Install Rust and cargo-based tooling.
if ! have_cmd cargo; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck source=/dev/null
source "$HOME/.cargo/env"

if ! have_cmd cargo-binstall; then
  curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
fi
cargo binstall -y prek worktrunk cargo-deny cargo-careful ast-grep

# actionlint — pre-built binary instead of go install.
if ! have_cmd actionlint; then
  ACTIONLINT_VERSION="1.7.11"
  download_file \
    "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
    /tmp/actionlint.tar.gz
  tar -xzf /tmp/actionlint.tar.gz -C /usr/local/bin actionlint
  rm -f /tmp/actionlint.tar.gz
fi
