#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# General Python packages used by the webapp, agents, and common CTF workflows.
uv_pip_install \
  pwntools ipython pycryptodome sympy z3-solver gmpy2 angr angrop unicorn zizmor \
  starlette uvicorn python-multipart itsdangerous websockets httpx requests \
  claude-agent-sdk google-auth

# Fast Python developer/security tools installed as uv-managed command-line tools.
uv_tool_install --force ruff
uv_tool_install --force ty
uv_tool_install --force pip-audit
