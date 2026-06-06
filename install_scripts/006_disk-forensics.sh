#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# Disk forensics tools for disk image analysis
#

apt_install \
  sleuthkit \
  ewf-tools \
  afflib-tools \
  kpartx \
  xmount \
  foremost \
  scalpel \
  testdisk \
  binwalk \
  qemu-utils \
  sqlite3

cp "$SCRIPT_DIR/artefacts/bulk_extractor" /usr/local/bin/bulk_extractor
chmod +x /usr/local/bin/bulk_extractor

uv_pip_install pytsk3
