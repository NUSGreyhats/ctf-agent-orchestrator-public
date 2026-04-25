#!/bin/bash
# Installs WireGuard and generates server keypair.
# Does NOT create a wg0 config — that's done via the web UI when the user
# provides their client public key and internal network CIDR.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

log "Installing WireGuard"
apt_update_quiet
apt_install -qq wireguard wireguard-tools resolvconf >/dev/null

WG_DIR="/etc/wireguard"
mkdir -p "$WG_DIR"
if [ ! -f "$WG_DIR/server_private.key" ]; then
  umask 077
  wg genkey > "$WG_DIR/server_private.key"
  wg pubkey < "$WG_DIR/server_private.key" > "$WG_DIR/server_public.key"
  log "WireGuard server keypair generated"
else
  log "WireGuard server keypair already exists, skipping"
fi

if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null

log "WireGuard installed. Configure via the web UI (VPN panel)."
