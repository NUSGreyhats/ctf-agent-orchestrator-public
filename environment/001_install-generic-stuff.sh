#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

mkdir -p "$HOME/.config/pip"
cat > "$HOME/.config/pip/pip.conf" << 'EOF'
[global]
break-system-packages = true
EOF

append_bashrc_line "export PATH=\"\$PATH:\$HOME/.local/bin\""
export PATH="$PATH:$HOME/.local/bin"

apt_update
apt_install \
  build-essential git curl wget python-is-python3 python3-pip python3-venv unzip p7zip-full \
  tmux neovim nmap \
  openjdk-21-jdk openjdk-21-jre \
  gdb ltrace strace \
  gcc-multilib g++-multilib \
  jq ripgrep shellcheck shfmt fd-find nodejs npm \
  ca-certificates

apt_remove \
  python3-jsonschema python3-rich python3-typing-extensions || true

install_uv

mkdir -p "$HOME/.local/bin"
if [ ! -e "$HOME/.local/bin/fd" ]; then
  ln -s "$(command -v fdfind)" "$HOME/.local/bin/fd"
fi

# Build ctfgrep (multi-encoding flag searcher for CTF challenges).
gcc -O2 -pthread -o /usr/local/bin/ctfgrep "$SCRIPT_DIR/artefacts/ctfgrep.c"
