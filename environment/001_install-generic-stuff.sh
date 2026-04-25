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

apt-get remove -y \
  python3-jsonschema python3-rich python3-typing-extensions || true

install_uv
uv_pip_install \
  pwntools ipython pycryptodome sympy z3-solver gmpy2 angr unicorn zizmor \
  starlette uvicorn python-multipart itsdangerous websockets httpx \
  claude-agent-sdk github-copilot-sdk opencode-sdk

uv tool install --force ruff
uv tool install --force ty
uv tool install --force pip-audit

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

npm_install_global oxlint agent-browser pnpm

mkdir -p "$HOME/.local/bin"
if [ ! -e "$HOME/.local/bin/fd" ]; then
  ln -s "$(command -v fdfind)" "$HOME/.local/bin/fd"
fi

# Build ctfgrep (multi-encoding flag searcher for CTF challenges).
gcc -O2 -pthread -o /usr/local/bin/ctfgrep "$SCRIPT_DIR/artefacts/ctfgrep.c"

# Install Docker.
install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi

cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt_update
apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
