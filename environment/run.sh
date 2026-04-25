#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

START=$SECONDS
mapfile -t SCRIPTS < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name '[0-9]*.sh' | sort)
TOTAL=${#SCRIPTS[@]}

if [ "$TOTAL" -eq 0 ]; then
  warn "No environment scripts found in $SCRIPT_DIR"
  exit 1
fi

index=0
for script in "${SCRIPTS[@]}"; do
  index=$((index + 1))
  name="$(basename "$script")"
  script_start=$SECONDS
  log "[$index/$TOTAL] Running $name"
  if bash "$script"; then
    elapsed=$((SECONDS - script_start))
    log "Completed $name in $((elapsed / 60))m $((elapsed % 60))s"
  else
    status=$?
    elapsed=$((SECONDS - script_start))
    warn "Failed $name after $((elapsed / 60))m $((elapsed % 60))s (exit $status)"
    exit "$status"
  fi
done

ELAPSED=$((SECONDS - START))
log "All scripts completed successfully in $((ELAPSED / 60))m $((ELAPSED % 60))s"
