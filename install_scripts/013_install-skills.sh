#!/bin/bash
# Install CTF skills into the runtime catalog used for per-challenge symlinks.

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install_scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

APP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_SKILLS="$APP_ROOT/skills"
ALL_SKILLS="$APP_ROOT/all-skills"
PROVIDER_SKILL_DIRS=(
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

install_skill_dir() {
  local skill_src="$1"
  local skill_name

  skill_name="$(read_skill_name "$skill_src/SKILL.md")"
  rm -rf "${ALL_SKILLS:?}/${skill_name:?}"
  cp -r "$skill_src" "$ALL_SKILLS/$skill_name"
}

install_repo_skills() {
  local skill_file skill_src skill_name

  while IFS= read -r -d '' skill_file; do
    skill_src="$(dirname "$skill_file")"
    skill_name="$(read_skill_name "$skill_file")"

    rm -rf "${ALL_SKILLS:?}/${skill_name:?}"
    cp -r "$skill_src" "$ALL_SKILLS/$skill_name"
  done < <(find "$REPO_SKILLS" -type f -name SKILL.md -print0 | sort -z)
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

remove_managed_provider_skills() {
  local dest="$1"
  local managed skill_name installed installed_skill_name provider_skill provider_skill_name

  mkdir -p "$dest"
  for managed in "$ALL_SKILLS"/*; do
    [ -d "$managed" ] || continue
    skill_name="$(basename "$managed")"
    installed="$dest/$skill_name"
    if [ -L "$installed" ]; then
      rm -f "$installed"
    elif [ -f "$installed/SKILL.md" ]; then
      installed_skill_name="$(read_skill_name "$installed/SKILL.md" || true)"
      if [ "$installed_skill_name" = "$skill_name" ]; then
        rm -rf "${installed:?}"
      fi
    fi
  done
  for provider_skill in "$dest"/*; do
    [ -f "$provider_skill/SKILL.md" ] || continue
    if provider_skill_name="$(read_skill_name "$provider_skill/SKILL.md")" \
      && [ -d "$ALL_SKILLS/$provider_skill_name" ]; then
      rm -rf "${provider_skill:?}"
    fi
  done
  remove_stale_group_dirs "$dest"
}

log "Installing skills to $ALL_SKILLS"
rm -rf "$ALL_SKILLS"
mkdir -p "$ALL_SKILLS"

install_repo_skills

for d in "$EXTERNAL_DIR"/*/; do
  name="$(basename "$d")"
  if [[ "$name" =~ ^($EXCLUDE)$ ]] || [ ! -f "$d/SKILL.md" ]; then
    continue
  fi
  install_skill_dir "$d"
done

for dest in "${PROVIDER_SKILL_DIRS[@]}"; do
  log "Removing managed global skills from $dest"
  remove_managed_provider_skills "$dest"
done

rm -rf "$EXTERNAL_DIR"
log "Skills installed to $ALL_SKILLS for challenge-local symlinks"
