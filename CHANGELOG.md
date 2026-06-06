# Changelog

## Unreleased

### Install Scripts Rename

Renamed the provisioning script directory from `environment/` to
`install_scripts/`. Terraform deploy syncs, setup commands, docs, and
shellcheck references now use the new path. The setup runner now uses
`INSTALL_SCRIPTS_PARALLEL` and `INSTALL_SCRIPTS_LOG_DIR`.

### IDA Pro via Skill

Restored the `analyze-with-ida-domain-api` skill for headless IDA Pro
analysis through IDA's Python Domain API. Claude/Codex agents load the skill
and write focused Python analysis scripts instead.

### HTB Multi-Answer Challenges

HTB `flagsInfo` questions are now imported and shown in the agent prompt.
Imported platform runs get a local `submit_answer.py` helper so agents can
submit arbitrary question answers (by question number or `flag_id`) instead
of relying on a fixed flag regex.

### Per-Challenge Statistics

Replaced the Tools sidebar tab with a Statistics tab showing per-run and
aggregate metrics:

- Token counts (input, output, cache read/write) for Claude and Codex
- Total cost (Claude), duration, API time, turns, tool calls
- Per-model breakdown from Claude's `model_usage` data
- Aggregate "Total" section summing across all runs

The cost/token display previously in the header bar has been removed in
favor of the stats panel.

### Challenge Status Fix

Fixed a bug where challenges stayed "solving" after the agent finished.
The finalization code that derives challenge status and broadcasts it to
the frontend was not protected against exceptions — if anything threw
(Discord notification, metadata save, etc.), the status broadcasts were
skipped and the challenge was stuck forever. Now wrapped in try/except
with the error surfaced in the chat feed.

Also fixed the SDK crash handler in `run_agent_task` which previously
re-raised the exception, skipping status updates entirely.

### Elapsed Timestamps

Each event from the agent is stamped with `ts` (seconds elapsed since
solve start). Timestamps display on text messages, thinking blocks, and
system messages in the chat feed.

### User Prompts in Chat

The initial prompt and resume/steer messages now appear as right-aligned
chat bubbles (labeled "Prompt" or "You"), making the conversation flow
visible. Codex `userMessage` and `contextCompaction` item types are now
handled instead of logged as unrecognized.

### WebSocket Reconnect Fix

Fixed a bug where the frontend reconnected to the WebSocket every 2
seconds unconditionally, even after the run finished. Each reconnection
replayed the full conversation history, causing the chat to duplicate.
Now skips reconnection when the run is in a terminal state.

### Documentation Update

Updated README.md and DESIGN.md to reflect current state:
- Added GCP as third cloud provider
- Added HTB CTF platform plugin
- Added Discord integration section
- Added per-challenge statistics
- Fixed state persistence paths
- Updated Supported Agents table
- Updated project structure and settings table

### Current Solving Model

The active challenge model is single or parallel runs with no manager agent.
Claude and Codex are the supported providers; Copilot and OpenCode have been
removed from the active webapp model.

Each challenge contains one or more runs. Each run has its own agent, output
stream, session state, WebSocket clients, working directory, notes file, and
skill selection. Parallel runs get isolated directories with symlinks to the
shared challenge files.

### Runtime Run Controls

Added run-level controls:

- stop one active agent without stopping sibling runs;
- stop all active agents from the challenge-level stop button;
- add one or more agents to an existing unsolved challenge;
- attach a run-specific custom prompt and skill list when adding agents.

Adding a run can promote a single challenge to parallel mode while preserving
the original run's notes.

### On-Demand Skills

Skills now load from the runtime `all-skills/` catalog. Challenge-level skills
are selected at creation/import time and locked afterward. Individual runs can
override their skill list mid-run; the wrapper stops the target run, refreshes
`.claude/skills` and `.codex/skills` symlinks, records a `run_skills` event,
and resumes by default.

The Settings page can upload a `.zip` skill bundle or single `SKILL.md` into
`all-skills/`, refresh the catalog, and select the uploaded skill as a global
default.

### Prompt Simplification

The initial prompt no longer lists the enabled skill catalog. It only adds
`Follow ctf-methodology and solve the CTF challenge` when `ctf-methodology`
is enabled. Resume/steer prompts are short continuation messages, and Discord
resume now uses `Continue solving the challenge`.

When challenge files are linked through `./challenge_files/`, the prompt now
keeps only the location line instead of a longer file-handling rule block.

### ctfgrep Preflight

Fresh runs silently execute `ctfgrep` before the agent starts. Matches are
added as detected flag candidates and auto-submitted when global auto-submit
is enabled. The scan output is not injected into the agent prompt.

Default command shape:

```bash
ctfgrep -i -m 4 -t 4 <target_dir> <term>
```

Default terms are `flag{`, `ctf{`, `picoCTF{`, and `HTB{`, unless challenge
flag formats provide prefixes. The timeout is 60 seconds per term.

### WireGuard Reverse VPN

WireGuard configuration now supports reverse routing for Linux clients. The
server routes configured client-side internal CIDRs to the client peer, while
the generated client config only routes the VPN subnet to the server. When
internal CIDRs are configured, the UI emits a Linux-only `wg-quick`/`iptables`
setup block for forwarding and NAT on the client router.

VPN status now shows latest handshake age.

### Agent Defaults

Claude now includes Opus 4.8 and defaults to Opus 4.6 (1M). Codex common
reasoning levels include Low, Medium, High, and XHigh, with XHigh as the
default when available.

### Un-solve

Solved challenges can be reverted to failed status if the flag turns out to
be wrong. All runs are stopped and the user can retry or steer.

**Why this exists:** In parallel mode, an agent might report a false flag
that triggers auto-stop of all other agents. The user needs a way to undo
this and get the agents working again.

### Bug Fix: WebSocket Set Iteration

Fixed a race condition in `broadcast()` where iterating over `ws_clients`
while `await`ing could fail with "set changed size during iteration" if a
WebSocket connected or disconnected during the loop.
