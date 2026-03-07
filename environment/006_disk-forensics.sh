#!/bin/bash

set -x
set -e

#
# Disk forensics tools for disk image analysis
#

# Core analysis: The Sleuth Kit, filesystem utilities
apt install -y \
    sleuthkit \
    ewf-tools \
    afflib-tools \
    kpartx \
    xmount

# File carving and data extraction
apt install -y \
    foremost \
    scalpel \
    testdisk \
    binwalk

# bulk_extractor (pre-built static binary)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/artefacts/bulk_extractor" /usr/local/bin/bulk_extractor
chmod +x /usr/local/bin/bulk_extractor

# Image format conversion
apt install -y \
    qemu-utils

# SQLite for artifact analysis (browser history, etc.)
apt install -y \
    sqlite3

# Python bindings for TSK
python3 -m pip install pytsk3
