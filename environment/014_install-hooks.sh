#!/bin/bash
# Install PostToolUse hooks for breakthrough notifications.
# Claude and Codex support hooks that inject messages between tool calls.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOKS_DIR="$SCRIPT_DIR/../hooks"
HOOK_SCRIPT="$(realpath "$HOOKS_DIR/check_breakthroughs.sh")"

echo "--- Installing breakthrough notification hooks ---"

# Claude Code: add PostToolUse hook to settings.json
CLAUDE_SETTINGS="$HOME/.claude/settings.json"
if [ -f "$CLAUDE_SETTINGS" ]; then
    python3 - "$CLAUDE_SETTINGS" "$HOOK_SCRIPT" <<'PYEOF'
import json, sys
settings_path, hook_script = sys.argv[1], sys.argv[2]
settings = json.loads(open(settings_path).read())
hooks = settings.setdefault("hooks", {})
post_hooks = hooks.setdefault("PostToolUse", [])

# Check if already installed
hook_cmd = hook_script
already = any(
    isinstance(h, dict) and hook_cmd in h.get("command", "")
    for h in post_hooks
)
if not already:
    post_hooks.append({
        "command": hook_cmd,
        "blocking": False,
    })
    open(settings_path, "w").write(json.dumps(settings, indent=2) + "\n")
    print("  Claude Code: PostToolUse hook installed")
else:
    print("  Claude Code: PostToolUse hook already present")
PYEOF
else
    echo "  Claude Code: settings.json not found, skipping"
fi

# Codex: add PostToolUse hook to hooks configuration
CODEX_DIR="$HOME/.codex"
if command -v codex &>/dev/null; then
    mkdir -p "$CODEX_DIR"
    CODEX_HOOKS="$CODEX_DIR/hooks.json"
    python3 - "$CODEX_HOOKS" "$HOOK_SCRIPT" <<'PYEOF'
import json, sys
hooks_path, hook_script = sys.argv[1], sys.argv[2]
try:
    hooks = json.loads(open(hooks_path).read())
except (FileNotFoundError, json.JSONDecodeError):
    hooks = {}

post_hooks = hooks.setdefault("PostToolUse", [])
hook_cmd = hook_script
already = any(
    isinstance(h, dict) and hook_cmd in h.get("command", "")
    for h in post_hooks
)
if not already:
    post_hooks.append({
        "command": hook_cmd,
        "blocking": False,
    })
    open(hooks_path, "w").write(json.dumps(hooks, indent=2) + "\n")
    print("  Codex: PostToolUse hook installed")
else:
    print("  Codex: PostToolUse hook already present")
PYEOF
else
    echo "  Codex: not installed, skipping"
fi

echo "--- Hooks installed ---"
