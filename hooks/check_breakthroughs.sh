#!/bin/bash
# PostToolUse hook: check for new breakthroughs from teammates.
# Outputs a notification if _shared/BREAKTHROUGHS.md has new content
# since last check. Silent (no output) if nothing new.
#
# Walks up from $PWD to find _shared/BREAKTHROUGHS.md (agent may be
# in a subdirectory).

DIR="${PWD}"
BREAKTHROUGHS=""

# Walk up to find _shared/BREAKTHROUGHS.md
while [ "$DIR" != "/" ]; do
    if [ -f "$DIR/_shared/BREAKTHROUGHS.md" ]; then
        BREAKTHROUGHS="$DIR/_shared/BREAKTHROUGHS.md"
        break
    fi
    DIR="$(dirname "$DIR")"
done

[ -z "$BREAKTHROUGHS" ] && exit 0

# Anchor cache to the discovered root, not PWD (which may be a subdir)
SEEN_FILE="${DIR}/.last_seen_breakthroughs"
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
