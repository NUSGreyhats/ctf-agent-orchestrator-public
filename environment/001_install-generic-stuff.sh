#!/bin/bash

set -x
set -e

mkdir -p ~/.config/pip/

cat > ~/.config/pip/pip.conf << 'EOF'
[global]
break-system-packages = true
EOF

echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
export PATH="$PATH:$HOME/.local/bin"

apt update
apt install -y \
    build-essential git curl wget python-is-python3 python3-pip unzip p7zip-full \
    tmux neovim nmap \
    openjdk-21-jdk openjdk-21-jre \
    gdb ltrace strace \
    gcc-multilib g++-multilib \
    jq ripgrep shellcheck shfmt fd-find nodejs npm \
    ca-certificates

python3 -m pip install pwntools ipython pycryptodome sympy z3-solver gmpy2 angr unicorn uv zizmor \
    starlette uvicorn python-multipart itsdangerous websockets httpx \
    claude-agent-sdk github-copilot-sdk opencode-sdk

uv tool install ruff
uv tool install ty
uv tool install pip-audit

# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# cargo-binstall downloads pre-built binaries instead of compiling from source
curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
cargo binstall -y prek worktrunk cargo-deny cargo-careful ast-grep
# actionlint — pre-built binary instead of go install
ACTIONLINT_VERSION="1.7.11"
wget -qO /tmp/actionlint.tar.gz \
    "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
tar -xzf /tmp/actionlint.tar.gz -C /usr/local/bin actionlint
rm -f /tmp/actionlint.tar.gz
npm install -g oxlint agent-browser pnpm


if [ ! -f "$HOME/.local/bin/fd" ]; then
    ln -s "$(which fdfind)" "$HOME/.local/bin/fd"
fi

# Build ctfgrep (multi-encoding flag searcher for CTF challenges)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
gcc -O2 -pthread -o /usr/local/bin/ctfgrep "$SCRIPT_DIR/artefacts/ctfgrep.c"

# install docker
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
