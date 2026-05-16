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

read_skill_name() {
  local skill_file="$1"
  local name

  name="$(awk '
    /^name:[[:space:]]*/ {
      sub(/^name:[[:space:]]*/, "")
      sub(/[[:space:]]+#.*$/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      gsub(/^"|"$/, "")
      print
      exit
    }
  ' "$skill_file")"

  if [ -z "$name" ]; then
    name="$(basename "$(dirname "$skill_file")")"
  fi

  if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    warn "Invalid skill name '$name' in $skill_file"
    return 1
  fi

  printf '%s\n' "$name"
}

install_repo_skills() {
  local dest="$1"
  local skill_file skill_src skill_name

  while IFS= read -r -d '' skill_file; do
    skill_src="$(dirname "$skill_file")"
    skill_name="$(read_skill_name "$skill_file")"

    rm -rf "${dest:?}/${skill_name:?}"
    cp -r "$skill_src" "$dest/$skill_name"
    remove_legacy_skill_dir "$dest" "$skill_src" "$skill_name"
  done < <(find "$REPO_SKILLS" -type f -name SKILL.md -print0 | sort -z)
}

remove_legacy_skill_dir() {
  local dest="$1"
  local skill_src="$2"
  local skill_name="$3"
  local legacy_name legacy_dir legacy_skill_name

  legacy_name="$(basename "$skill_src")"
  legacy_dir="$dest/$legacy_name"
  if [ "$legacy_name" = "$skill_name" ] || [ ! -f "$legacy_dir/SKILL.md" ]; then
    return 0
  fi

  if legacy_skill_name="$(read_skill_name "$legacy_dir/SKILL.md")" \
    && [ "$legacy_skill_name" = "$skill_name" ]; then
    rm -rf "${dest:?}/${legacy_name:?}"
  fi
}

remove_stale_group_dirs() {
  local dest="$1"
  local group

  for group in forensics tools; do
    if [ -d "$dest/$group" ] && [ ! -f "$dest/$group/SKILL.md" ]; then
      rm -rf "${dest:?}/${group:?}"
    fi
  done
}

for dest in "${SKILL_DIRS[@]}"; do
  log "Installing skills to $dest"
  mkdir -p "$dest"

  install_repo_skills "$dest"
  remove_stale_group_dirs "$dest"

  for d in "$EXTERNAL_DIR"/*/; do
    name="$(basename "$d")"
    if [[ "$name" =~ ^($EXCLUDE)$ ]]; then
      continue
    fi
    rm -rf "${dest:?}/${name:?}"
    cp -r "$d" "$dest/"
  done
done

rm -rf "$EXTERNAL_DIR"
log "Skills installed to ${#SKILL_DIRS[@]} agent directories"
