#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

START=$SECONDS
PARALLEL_MODE="${ENVIRONMENT_PARALLEL:-1}"
LOG_BASE="${ENVIRONMENT_LOG_DIR:-/var/log/ctf-agent-wrapper/environment}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="$LOG_BASE/$RUN_ID"

if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
  LOG_DIR="$SCRIPT_DIR/.logs/$RUN_ID"
  mkdir -p "$LOG_DIR"
fi

script_path() {
  printf '%s/%s\n' "$SCRIPT_DIR" "$1"
}

format_duration() {
  local seconds="$1"
  printf '%dm %ds' "$((seconds / 60))" "$((seconds % 60))"
}

run_one() {
  local name="$1"
  local script
  script="$(script_path "$name")"
  local log_file="$LOG_DIR/${name%.sh}.log"
  local script_start=$SECONDS

  if [ ! -f "$script" ]; then
    warn "Missing environment script: $name"
    return 1
  fi

  log "Running $name (log: $log_file)"
  if bash "$script" >"$log_file" 2>&1; then
    local elapsed=$((SECONDS - script_start))
    log "Completed $name in $(format_duration "$elapsed")"
    return 0
  else
    local status=$?
    local elapsed=$((SECONDS - script_start))
    warn "Failed $name after $(format_duration "$elapsed") (exit $status)"
    warn "Last 80 log lines from $log_file:"
    tail -n 80 "$log_file" >&2 || true
    return "$status"
  fi
}

run_sequential() {
  local scripts=("$@")
  local total=${#scripts[@]}
  local index=0

  if [ "$total" -eq 0 ]; then
    warn "No environment scripts to run"
    return 1
  fi

  for name in "${scripts[@]}"; do
    index=$((index + 1))
    log "[$index/$total] Sequential step: $name"
    run_one "$name"
  done
}

run_parallel_group() {
  local group_name="$1"
  shift
  local scripts=("$@")
  local total=${#scripts[@]}

  if [ "$total" -eq 0 ]; then
    return 0
  fi

  log "Starting parallel group '$group_name' with $total script(s)"

  local pids=()
  local names=()
  local name
  for name in "${scripts[@]}"; do
    run_one "$name" &
    pids+=("$!")
    names+=("$name")
  done

  local failed=0
  local status=0
  local i
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      continue
    else
      status=$?
      warn "Parallel group '$group_name' script failed: ${names[$i]} (exit $status)"
      failed=1
    fi
  done

  if [ "$failed" -ne 0 ]; then
    return 1
  fi

  log "Completed parallel group '$group_name'"
}

run_dependency_graph() {
  local bootstrap=(
    001_install-generic-stuff.sh
  )
  local parallel_group_a=(
    002_reverse-engineering.sh
    004_network-forensics.sh
    005_memory-forensics.sh
    006_disk-forensics.sh
    007_file-forensics.sh
    008_install-copilot-cli.sh
    009_install-crypto.sh
    011_install-opencode.sh
    012_install-wireguard.sh
    013_install-skills.sh
    015_install-python-tooling.sh
    016_install-rust-tooling.sh
    017_install-node-tooling.sh
    018_install-docker.sh
  )
  local parallel_group_b=(
    003_install-claude-code.sh
    010_install-codex.sh
  )
  local final=(
    014_install-hooks.sh
    990_validate.sh
  )

  run_sequential "${bootstrap[@]}"
  run_parallel_group independent-tooling "${parallel_group_a[@]}"
  run_parallel_group agent-registration "${parallel_group_b[@]}"
  run_sequential "${final[@]}"
}

mapfile -t ALL_SCRIPTS < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name '[0-9]*.sh' -printf '%f\n' | sort)

if [ "${#ALL_SCRIPTS[@]}" -eq 0 ]; then
  warn "No environment scripts found in $SCRIPT_DIR"
  exit 1
fi

log "Environment logs: $LOG_DIR"

if [[ "$PARALLEL_MODE" == "0" || "$PARALLEL_MODE" == "false" || "$PARALLEL_MODE" == "no" ]]; then
  log "Running environment setup sequentially (ENVIRONMENT_PARALLEL=$PARALLEL_MODE)"
  run_sequential "${ALL_SCRIPTS[@]}"
else
  log "Running environment setup with dependency-aware parallelism"
  run_dependency_graph
fi

ELAPSED=$((SECONDS - START))
log "All scripts completed successfully in $(format_duration "$ELAPSED")"
