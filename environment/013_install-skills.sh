#!/bin/bash
# Install CTF skills to all agent skill directories.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

REPO_SKILLS="$SCRIPT_DIR/../skills"
SKILL_DIRS=(
  "$HOME/.claude/skills"
  "$HOME/.codex/skills"
)

EXTERNAL_DIR="/tmp/ljagiello-ctf-skills"
rm -rf "$EXTERNAL_DIR"
log "Cloning ljagiello/ctf-skills"
git clone --depth 1 https://github.com/ljagiello/ctf-skills.git "$EXTERNAL_DIR"

EXCLUDE="solve-challenge|ctf-forensics|ctf-writeup|scripts|tests|.github"

for dest in "${SKILL_DIRS[@]}"; do
  log "Installing skills to $dest"
  mkdir -p "$dest"

  cp -r "$REPO_SKILLS/"* "$dest/"

  for d in "$EXTERNAL_DIR"/*/; do
    name="$(basename "$d")"
    if [[ "$name" =~ ^($EXCLUDE)$ ]]; then
      continue
    fi
    cp -r "$d" "$dest/"
  done
done

rm -rf "$EXTERNAL_DIR"
log "Skills installed to ${#SKILL_DIRS[@]} agent directories"
