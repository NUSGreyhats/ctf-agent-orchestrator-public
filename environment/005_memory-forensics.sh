#!/bin/bash

set -x
set -e

#
# Memory forensics tools: Volatility 3, symbol tables, and mquire
#

# Volatility 3 and plugin dependencies
python3 -m pip install volatility3 yara-python capstone

# Download official symbol table packs
VOL_SYMBOLS=$(python3 -c "import volatility3.symbols; import os; print(os.path.dirname(volatility3.symbols.__file__))")

wget -P "$VOL_SYMBOLS" https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
wget -P "$VOL_SYMBOLS" https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
wget -P "$VOL_SYMBOLS" https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip

# Verify downloads
wget -qO /tmp/vol3_SHA256SUMS https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS
cd "$VOL_SYMBOLS" && sha256sum -c /tmp/vol3_SHA256SUMS && cd -
rm -f /tmp/vol3_SHA256SUMS

# Install pre-built symbol cache
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
tar -xzf "$SCRIPT_DIR/artefacts/vol3-cache.tar.gz" -C /

# mquire (Linux memory analysis using BTF, no symbol tables needed)
MQUIRE_VERSION="1.2.3"
wget -qO /tmp/mquire.tar.gz \
    "https://github.com/trailofbits/mquire/releases/download/${MQUIRE_VERSION}/mquire-${MQUIRE_VERSION}-1.x86_64.tar.gz"
tar -xzf /tmp/mquire.tar.gz -C /usr/local/bin --strip-components=2
rm -f /tmp/mquire.tar.gz
