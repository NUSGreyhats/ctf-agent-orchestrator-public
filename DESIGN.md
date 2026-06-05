# Design: Challenge Solving Workflow

## Goals

`ctf-agent-wrapper` is a single-VM CTF workstation. The webapp stores challenges, starts one or more AI agents, streams agent output to authenticated browsers, and persists enough metadata to resume or audit runs after restarts.

The important design constraints are:

- agents should have a rich local toolchain and permissive execution environment;
- uploaded challenge files should not be able to masquerade as provider config, tools, hooks, or repository files;
- multiple agents should be able to work independently but share validated breakthroughs;
- runtime data should survive webapp restarts and deploy syncs.

## Solving Modes

### Single

One agent works on the challenge. New single-mode challenges still use a clean per-run working directory:

```text
challenges/{id}/
  _files/                  # uploaded/imported challenge files
  _runs/{run_id}/          # provider cwd
    challenge_files/       # symlink tree to ../../_files
```

Legacy single challenges that predate `_runs/{run_id}` are still supported by falling back to the challenge root.

### Parallel

Multiple agents work on the same challenge simultaneously. Each agent works in its own isolated run directory, maintains its own notes, and shares validated breakthroughs with teammates via the `notify_teammates` tool and shared notes symlinks.

When any run is marked solved or submits a correct flag, the solved run is stopped if still active, sibling runs are stopped, status is persisted, and all connected clients receive run/challenge status updates.

## Agent Collaboration Model

Parallel mode collaboration has two channels:

1. **`notify_teammates` tool** — agents call this for validated breakthroughs.
2. **Working notes** — agents maintain markdown notes that teammates can read through symlinks.

### Working Notes

Each parallel agent maintains a structured notes file:

```markdown
# Working Notes — {agent}
## Challenge Understanding
## Hypotheses
[ ] untested  [x] failed  [>] active
## Key Findings
## Tools & Techniques Tried
## Dead Ends
## Next Steps
```

Agents update this file continuously. It serves as persistent memory that survives context compaction and as a reference for teammates.

### `notify_teammates` Tool

Provider implementations expose collaboration as follows:

- **Claude**: in-process MCP tool via `create_sdk_mcp_server`.
- **Codex**: dynamic tool in `thread/start` `dynamicTools`.
- **Copilot**: SDK `define_tool` handler.
- **OpenCode**: TypeScript tool installed under `~/.config/opencode/tools/notify_teammates.ts`; the SDK path also polls the shared queue file.

When an agent calls `notify_teammates`:

1. The tool handler writes to an in-memory queue or the shared OpenCode queue file.
2. The receiving provider poller picks up the message.
3. The message is injected into teammates' sessions as a teammate breakthrough.
4. Delivery happens at natural turn boundaries where possible, rather than interrupting an active tool call.

Users can also broadcast a message from the web UI or Discord. User broadcasts are injected into all active runs as `[User]` breakthrough messages.

## File System Layout

Uploaded/imported files are stored under `_files/` for **all new challenges**. Provider working directories are under `_runs/{run_id}/`. Agents should use `./challenge_files/` for challenge data.

### Single Mode

```text
challenges/{id}/
  _files/
    chall.bin
    nested/input.txt
  _runs/
    {run_id}/
      challenge_files/
        chall.bin -> ../../_files/chall.bin
        nested/
          input.txt -> ../../../_files/nested/input.txt
      WORKING_NOTES.md
      solver.py
      extracted-output.txt
```

### Parallel Mode

```text
challenges/{id}/
  _files/
    chall.bin
  _shared/
    .notify_queue                # OpenCode collaboration queue when used
  _runs/
    {run_id_1}/
      challenge_files/
        chall.bin -> ../../_files/chall.bin
      _shared -> ../../_shared
      WORKING_NOTES_claude.md
      WORKING_NOTES_codex.md -> ../{run_id_2}/WORKING_NOTES_codex.md
    {run_id_2}/
      challenge_files/
        chall.bin -> ../../_files/chall.bin
      _shared -> ../../_shared
      WORKING_NOTES_codex.md
      WORKING_NOTES_claude.md -> ../{run_id_1}/WORKING_NOTES_claude.md
```

### File Access Rules

- Web file listing defaults to original challenge files.
- Selecting a run in the Files tab shows that run's workspace.
- Single-run challenges default to the run workspace so generated artifacts are visible.
- File view/download paths are resolved server-side and must stay under allowed roots.
- Symlink targets are resolved and filtered so a symlink cannot expose unrelated system paths.
- Discord `/files` uses the same safe path-resolution model and enforces a display-size cap.

## Agent Execution

All providers currently use SDK/integration paths:

| Provider | Integration | Protocol |
|----------|-------------|----------|
| Claude | `claude-agent-sdk` | Native Python client, typed messages |
| Codex | `codex app-server` | JSON-RPC 2.0 over stdio |
| Copilot | `github-copilot-sdk` | Python SDK with event callbacks |
| OpenCode | `opencode-sdk` | REST API to `opencode serve` on `127.0.0.1` |

Provider modules still keep command builders and normalizers for compatibility/fallback behavior, but normal webapp runs go through the SDK-style `run_agent` path.

Each run stores provider session state in challenge metadata, for example:

- Claude session id;
- Codex thread id;
- OpenCode session id.

Resume uses this state when possible. Retry clears run output and session state.

## Status and Solve Lifecycle

Challenge status is derived from run statuses:

- `solved` if any run is solved;
- `solving` if any run is solving;
- `pending` if any run is pending;
- `failed` if all runs failed;
- `completed` if all non-failed terminal runs completed.

Solve paths are centralized so web, Discord, plugin submit, and auto-submit behave consistently:

1. mark the target run solved;
2. persist the correct flag if present;
3. stop the solved run if it is still active;
4. stop sibling parallel runs;
5. save metadata;
6. broadcast run and challenge status updates;
7. notify Discord when enabled.

Stop paths similarly set affected runs to `failed`, append a stop event, persist metadata, and broadcast updates.

## CTF Platform Plugins

Three platform plugins are supported:

| Plugin | Auth | Features |
|--------|------|----------|
| CTFd | API token or username/password | Fetch challenges, download files, submit flags |
| rCTF | Auth token or team token | Fetch challenges, download files, submit flags |
| HTB CTF | JWT Bearer token | Fetch challenges, download files, submit flags, on-demand instance management |

CTFd and rCTF verify TLS by default. They expose an explicit `insecure_tls` checkbox for self-signed/local deployments. HTB uses normal certificate verification.

HTB challenges with Docker/machine instances are started at solve time, not import time, to respect concurrent instance limits. Connection info (`url`, `host`, `port`, `connection`) is injected into the agent prompt.

HTB multi-answer challenge metadata (`flagsInfo`) is preserved as `_flag_questions`. The prompt lists each question and run workspaces include `submit_answer.py`, which calls a local token-protected endpoint to submit arbitrary answers by question number or platform `flag_id`.

Connections are persisted to `state/connections.json` and can be synced to fetch new challenges from already-imported platforms.

## Discord Integration

When enabled, the Discord bot connects via the Discord gateway WebSocket and registers slash commands.

Features:

- per-challenge Discord destinations created when challenges are created/imported with Discord enabled;
- layout setting for either one thread per challenge in the selected announcement channel or one text channel per challenge under a Discord category matching the challenge category;
- destination rename on completion (`[solved]` thread prefix or `solved-` channel prefix);
- notifications for starts, stops, solves, flag detections, and breakthroughs;
- flag review buttons on detected candidates for submit, reject, mark correct, and broadcast;
- challenge action buttons for status, stats, tail, flags, submit flag, mark solved, stop, and resume;
- slash commands: `/broadcast`, `/submit`, `/status`, `/flags`, `/stop`, `/resume`, `/solved`, `/ctf`, `/files`.

Changing Discord settings in the web UI reconciles the gateway: it starts when enabled, stops when disabled, and restarts when token/channel/guild settings change.

## Web Security Model

The webapp is protected by HTTP Basic/session authentication. State-changing HTTP routes require a CSRF token. WebSockets require authentication and validate `Origin` against either same-origin or the `ALLOWED_ORIGINS` environment variable.

Browser hardening headers are added by middleware:

- Content-Security-Policy;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `X-Frame-Options: DENY`;
- `Permissions-Policy`;
- `Cross-Origin-Opener-Policy`;
- HSTS when TLS is enabled.

## Deployment Model

Terraform supports Hetzner Cloud, DigitalOcean, and GCP.

Deploy syncs use a runtime allowlist instead of copying the entire repository. The copied paths are:

```text
environment
webapp
skills
mcps
hooks
README.md
DESIGN.md
```

The deploy intentionally does **not** copy local `.git/`, `infra/`, Terraform state/vars, provider caches, or other local repo artifacts. Python bytecode/cache files are excluded from sync and sync hashing.

Remote runtime data is preserved during sync:

```text
/root/ctf-agent-wrapper/challenges
/root/ctf-agent-wrapper/state
```

DigitalOcean and GCP provisioners include a `sync_hash` trigger so runtime changes cause a new sync and service restart. Hetzner splits sync, environment setup, and webapp restart into separate resources; skill changes are included in the environment setup hash because skills are installed into agent skill directories.

## Environment Setup

Environment scripts remain numbered and executable by `environment/run.sh`, but share common helper functions from `environment/lib/common.sh` for logging, retries, package installs, downloads, package-manager locks, and shell-profile updates. By default, `run.sh` uses a dependency-aware parallel plan: the base bootstrap runs first, independent tooling categories run concurrently, agent registration runs after the local MCP tooling is available, and validation runs last. Set `ENVIRONMENT_PARALLEL=0` to force the old sequential order.

Most Python dependencies are installed with:

```bash
uv pip install --system ...
```

This keeps the disposable VM's global Python workflow while improving install speed and resolver/cache behavior. `python3 -m pip` is retained only for vendor-local wheels such as IDA's `idapro*.whl`.

The last setup script, `environment/990_validate.sh`, validates critical commands and Python imports. It catches incomplete provisioning before the webapp is used.

## Persistence

Runtime state locations:

| Data | Path |
|------|------|
| Challenge metadata | `state/{challenge_id}/challenge.json` |
| Per-run output log | `state/{challenge_id}/{run_id}.jsonl` |
| Platform connections | `state/connections.json` |
| Global settings | `challenges/settings.json` |
| Original challenge files | `challenges/{challenge_id}/_files/` |
| Per-run workspace | `challenges/{challenge_id}/_runs/{run_id}/` |

On startup, stale `solving` runs are reset to `failed` because agent subprocesses/tasks do not survive a webapp restart. Legacy challenge metadata/output locations are migrated into `state/` when possible.

## Settings

Settings persist to `challenges/settings.json`.

| Setting | Default | Description |
|---------|---------|-------------|
| `default_agent` | `claude` | Default agent for new challenges |
| `default_flag_format` | empty | Default flag format |
| `theme` | `dark` | UI theme |
| `auto_submit_flags` | `false` | Auto-submit detected flags to CTF platform |
| `chat_view_mode` | `split` | Agent view layout: `split` or `tabbed` |
| `enabled_agents` | empty | Which agents appear in the agent selector; empty means default behavior |
| `agent_models` | `{}` | Per-agent default model overrides |
| `agent_efforts` | `{}` | Per-agent default effort overrides |
| `max_platform_import_size_gb` | `2.0` | Per-challenge cap for platform-imported files; challenges exceeding it are skipped |
| `discord_enabled` | `false` | Enable Discord bot integration |
| `discord_bot_token` | empty | Discord bot token |
| `discord_channel_id` | empty | Discord announcement channel; also the parent channel for thread mode |
| `discord_guild_id` | empty | Discord guild for slash command registration |
| `discord_challenge_layout` | `threads` | Discord challenge destination mode: `threads` or `channels` |
