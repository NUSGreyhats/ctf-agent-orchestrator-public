#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# Network forensics tools for pcap/pcapng analysis
#

# Pre-answer tshark debconf prompt (allow non-root packet capture).
printf '%s\n' "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

apt_install \
  tshark \
  tcpdump \
  ngrep \
  tcpflow \
  chaosreader \
  foremost \
  dsniff \
  ssldump

uv_pip_install scapy pyshark dpkt
