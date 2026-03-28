#!/bin/bash
# Install CTF skills to all agent skill directories.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_SKILLS="$SCRIPT_DIR/../skills"

# Skill directories for each agent
SKILL_DIRS=(
    "$HOME/.claude/skills"
    "$HOME/.codex/skills"
)

# Clone external skills once
EXTERNAL_DIR="/tmp/ljagiello-ctf-skills"
rm -rf "$EXTERNAL_DIR"
echo "--- Cloning ljagiello/ctf-skills ---"
git clone --depth 1 https://github.com/ljagiello/ctf-skills.git "$EXTERNAL_DIR"

EXCLUDE="solve-challenge|ctf-forensics|ctf-writeup|scripts|tests|.github"

for dest in "${SKILL_DIRS[@]}"; do
    echo "--- Installing skills to $dest ---"
    mkdir -p "$dest"

    # Copy repo skills (methodology, forensics, tools)
    cp -r "$REPO_SKILLS/"* "$dest/"

    # Copy external category skills
    for d in "$EXTERNAL_DIR"/*/; do
        name="$(basename "$d")"
        if echo "$name" | grep -qE "^($EXCLUDE)$"; then
            continue
        fi
        cp -r "$d" "$dest/"
    done
done

rm -rf "$EXTERNAL_DIR"
echo "--- Skills installed to ${#SKILL_DIRS[@]} agent directories ---"
