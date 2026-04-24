#!/bin/bash

set -euo pipefail
set -x

npm install -g opencode-ai@latest
opencode --version

# Register local GDB MCP server for OpenCode in global config.
python3 - <<'PY'
import json
from pathlib import Path

config_path = Path.home() / ".config" / "opencode" / "opencode.json"
config_path.parent.mkdir(parents=True, exist_ok=True)

if config_path.exists():
    raw = config_path.read_text()
    try:
        config = json.loads(raw)
    except json.JSONDecodeError:
        print(
            f"Warning: {config_path} is not strict JSON; "
            "skipping automatic GDB MCP registration."
        )
        raise SystemExit(0)
else:
    config = {}

if not isinstance(config, dict):
    config = {}

config.setdefault("$schema", "https://opencode.ai/config.json")
mcp = config.setdefault("mcp", {})
if not isinstance(mcp, dict):
    mcp = {}
    config["mcp"] = mcp

mcp["gdb"] = {
    "type": "local",
    "command": ["python3", "/root/ctf-agent-wrapper/mcps/gdb_mcp.py"],
    "enabled": True,
}
mcp["ida"] = {
    "type": "local",
    "command": ["ida-mcp"],
    "env": {"IDADIR": "/opt/ida-pro-9.3"},
    "enabled": True,
}

config_path.write_text(json.dumps(config, indent=2) + "\n")
PY

# Print MCP status for visibility, but don't fail setup on CLI list issues.
opencode mcp list || true
