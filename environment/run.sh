#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START=$SECONDS

for script in "$SCRIPT_DIR"/[0-9]*.sh; do
  echo "=== Running $(basename "$script") ==="
  bash "$script"
done

ELAPSED=$((SECONDS - START))
echo "=== All scripts completed successfully in $((ELAPSED / 60))m $((ELAPSED % 60))s ==="
