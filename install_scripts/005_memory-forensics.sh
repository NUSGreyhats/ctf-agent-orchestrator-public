#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# Memory forensics tools: Volatility 3, symbol tables, and mquire
#

uv_pip_install volatility3 yara-python capstone

VOL_SYMBOLS=$(python3 -c "import volatility3.symbols; import os; print(os.path.dirname(volatility3.symbols.__file__))")

download_file https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip "$VOL_SYMBOLS/windows.zip"
download_file https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip "$VOL_SYMBOLS/mac.zip"
download_file https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip "$VOL_SYMBOLS/linux.zip"

download_file https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS /tmp/vol3_SHA256SUMS
(
  cd "$VOL_SYMBOLS"
  sha256sum -c /tmp/vol3_SHA256SUMS
)
rm -f /tmp/vol3_SHA256SUMS

CACHE_MARKER="/var/lib/ctf-agent-wrapper/vol3-cache.installed"
if [ ! -f "$CACHE_MARKER" ]; then
  mkdir -p "$(dirname "$CACHE_MARKER")"
  tar -xzf "$SCRIPT_DIR/artefacts/vol3-cache.tar.gz" -C /
  touch "$CACHE_MARKER"
fi

if ! have_cmd mquire; then
  MQUIRE_VERSION="1.2.3"
  download_file \
    "https://github.com/trailofbits/mquire/releases/download/${MQUIRE_VERSION}/mquire-${MQUIRE_VERSION}-1.x86_64.tar.gz" \
    /tmp/mquire.tar.gz
  tar -xzf /tmp/mquire.tar.gz -C /usr/local/bin --strip-components=2
  rm -f /tmp/mquire.tar.gz
fi
