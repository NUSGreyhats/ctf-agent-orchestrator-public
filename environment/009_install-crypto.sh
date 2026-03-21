#!/bin/bash

set -x
set -e

#
# Crypto tools: password cracking, CAS, and Python libraries
#

# Core crypto tooling
DEBIAN_FRONTEND=noninteractive apt install -y \
    hashcat \
    john

# SageMath: install from conda-forge via Miniforge.
# This follows Sage's installation guide for Linux when distro packaging is unsuitable.
MINIFORGE_DIR="/opt/miniforge3"
MINIFORGE_INSTALLER="/tmp/Miniforge3-$(uname)-$(uname -m).sh"

if [ ! -x "$MINIFORGE_DIR/bin/conda" ]; then
    wget -qO "$MINIFORGE_INSTALLER" \
        "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh"
    bash "$MINIFORGE_INSTALLER" -b -p "$MINIFORGE_DIR"
    rm -f "$MINIFORGE_INSTALLER"
fi

"$MINIFORGE_DIR/bin/conda" config --system --set channel_priority strict
"$MINIFORGE_DIR/bin/conda" config --system --add channels conda-forge

if "$MINIFORGE_DIR/bin/conda" env list | awk '{print $1}' | grep -qx sage; then
    "$MINIFORGE_DIR/bin/conda" env remove -y -n sage
fi

"$MINIFORGE_DIR/bin/conda" create -y -n sage sage python=3.12
"$MINIFORGE_DIR/bin/conda" clean -a -y

cat > /usr/local/bin/sage << 'EOF'
#!/usr/bin/bash
exec /opt/miniforge3/envs/sage/bin/sage "$@"
EOF
chmod +x /usr/local/bin/sage

# Python libraries for scripting and algebraic attacks
python3 -m pip install --break-system-packages \
    gmpy2 \
    pycryptodome \
    z3-solver
