#!/bin/bash

set -x
set -e

#
# Network forensics tools for pcap/pcapng analysis
#

# Pre-answer tshark debconf prompt (allow non-root packet capture)
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# Core analysis tools
DEBIAN_FRONTEND=noninteractive apt install -y \
    tshark \
    tcpdump \
    ngrep \
    tcpflow \
    chaosreader \
    foremost \
    dsniff \
    ssldump

# Python libraries for programmatic packet analysis
python3 -m pip install scapy pyshark dpkt
