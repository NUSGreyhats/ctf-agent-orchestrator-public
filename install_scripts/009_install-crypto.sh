#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# Crypto tools: password cracking, CAS, and Python libraries
#

apt_install hashcat john

# SageMath: install from conda-forge via Miniforge.
MINIFORGE_DIR="/opt/miniforge3"
MINIFORGE_INSTALLER="/tmp/Miniforge3-$(uname)-$(uname -m).sh"

if [ ! -x "$MINIFORGE_DIR/bin/conda" ]; then
  download_file \
    "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh" \
    "$MINIFORGE_INSTALLER"
  bash "$MINIFORGE_INSTALLER" -b -p "$MINIFORGE_DIR"
  rm -f "$MINIFORGE_INSTALLER"
fi

"$MINIFORGE_DIR/bin/conda" config --system --set channel_priority strict
"$MINIFORGE_DIR/bin/conda" config --system --add channels conda-forge

if ! "$MINIFORGE_DIR/bin/conda" run -n sage sage --version >/dev/null 2>&1; then
  if "$MINIFORGE_DIR/bin/conda" env list | awk '{print $1}' | grep -qx sage; then
    "$MINIFORGE_DIR/bin/conda" env remove -y -n sage
  fi
  "$MINIFORGE_DIR/bin/conda" create -y -n sage sage python=3.12
  "$MINIFORGE_DIR/bin/conda" clean -a -y
fi

cat > /usr/local/bin/sage << 'EOF'
#!/usr/bin/bash
exec /opt/miniforge3/envs/sage/bin/sage "$@"
EOF
chmod +x /usr/local/bin/sage

uv_pip_install gmpy2 pycryptodome z3-solver
