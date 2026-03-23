#!/usr/bin/env bash
set -euo pipefail

# Memory forensics tool installer
# Installs volatility3 and mquire if not already present

WORK_DIR="${1:-/tmp/memforensics}"
mkdir -p "$WORK_DIR"

echo "=== Memory Forensics Setup ==="

# --- Volatility 3 ---
if python3 -c "import volatility3" 2>/dev/null; then
  echo "[OK] volatility3 already installed"
else
  echo "[*] Installing volatility3..."
  pip install volatility3 2>&1 | tail -3
  if python3 -c "import volatility3" 2>/dev/null; then
    echo "[OK] volatility3 installed"
  else
    echo "[WARN] volatility3 installation failed"
  fi
fi

# Check vol CLI availability
if command -v vol &>/dev/null; then
  echo "[OK] vol CLI available: $(which vol)"
else
  # Try as python module
  if python3 -m volatility3.cli --help &>/dev/null; then
    echo "[OK] volatility3 available via: python3 -m volatility3.cli"
  else
    echo "[WARN] vol CLI not in PATH, will use python3 -m volatility3.cli"
  fi
fi

# --- mquire ---
if command -v mquire &>/dev/null; then
  echo "[OK] mquire already installed: $(which mquire)"
else
  echo "[*] Installing mquire..."
  if command -v cargo &>/dev/null; then
    cargo install --git https://github.com/trailofbits/mquire 2>&1 | tail -3
    if command -v mquire &>/dev/null; then
      echo "[OK] mquire installed"
    else
      echo "[INFO] mquire built but may need PATH update (~/.cargo/bin)"
      export PATH="$HOME/.cargo/bin:$PATH"
    fi
  else
    echo "[*] cargo not found, trying to install via rustup..."
    if command -v rustup &>/dev/null; then
      rustup default stable
    else
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      source "$HOME/.cargo/env"
    fi
    cargo install --git https://github.com/trailofbits/mquire 2>&1 | tail -3
    echo "[OK] mquire installed"
  fi
fi

# --- strings (should be pre-installed on most systems) ---
if command -v strings &>/dev/null; then
  echo "[OK] strings available"
else
  echo "[*] Installing binutils for strings..."
  apt-get update -qq && apt-get install -y -qq binutils 2>&1 | tail -1
fi

echo ""
echo "=== Setup complete ==="
