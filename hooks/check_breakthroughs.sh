#!/bin/bash
# PostToolUse hook: check for new breakthroughs from teammates.
# Outputs a notification if _shared/BREAKTHROUGHS.md has new content
# since last check. Silent (no output) if nothing new.
#
# Usage: check_breakthroughs.sh <run_dir>
# The run_dir should contain _shared/ symlink.

RUN_DIR="${1:-$(pwd)}"
BREAKTHROUGHS="$RUN_DIR/_shared/BREAKTHROUGHS.md"
SEEN_FILE="$RUN_DIR/.last_seen_breakthroughs"

[ ! -f "$BREAKTHROUGHS" ] && exit 0

CURRENT_HASH=$(md5sum "$BREAKTHROUGHS" 2>/dev/null | cut -d' ' -f1)
LAST_HASH=$(cat "$SEEN_FILE" 2>/dev/null)

# No change since last check
[ "$CURRENT_HASH" = "$LAST_HASH" ] && exit 0

# First check — just record the hash, don't notify
if [ -z "$LAST_HASH" ]; then
    echo "$CURRENT_HASH" > "$SEEN_FILE"
    exit 0
fi

# New content — update hash and notify
echo "$CURRENT_HASH" > "$SEEN_FILE"
echo "[Team Update] A teammate posted a breakthrough. Read _shared/BREAKTHROUGHS.md when you have a moment."
