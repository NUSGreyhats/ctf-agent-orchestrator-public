#!/bin/bash
# Installs WireGuard and generates server keypair.
# Does NOT create a wg0 config — that's done via the web UI when the user
# provides their client public key and internal network CIDR.

set -euo pipefail

echo "--- Installing WireGuard ---"

apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools resolvconf > /dev/null

# Generate server keypair (only on first run)
WG_DIR="/etc/wireguard"
if [ ! -f "$WG_DIR/server_private.key" ]; then
  umask 077
  wg genkey > "$WG_DIR/server_private.key"
  wg pubkey < "$WG_DIR/server_private.key" > "$WG_DIR/server_public.key"
  echo "WireGuard server keypair generated."
else
  echo "WireGuard server keypair already exists, skipping."
fi

# Enable IP forwarding (persistent)
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "WireGuard installed. Configure via the web UI (VPN panel)."
