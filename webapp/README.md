# CTF Solver Web App

A web application that uses AI coding agents (Claude Code, Codex, GitHub Copilot CLI, and OpenCode) to solve CTF challenges. Upload challenge files, describe the problem, and watch an agent work through it in real time.

## Architecture

```
webapp/
  app.py              # Starlette backend (API + WebSocket)
  start.sh            # Startup script (generates creds, TLS cert)
  ctf-solver.service  # systemd unit file
  static/
    index.html         # Single-page app
    app.js             # Frontend logic
    style.css          # Dark theme UI
```

The backend spawns provider-specific CLI processes in non-interactive mode, normalizes their JSON or JSONL event streams into a shared UI format, and persists challenge state to `/root/.ctf-solver-state` so solver metadata stays out of challenge working directories.

Methodology and domain skills are read directly from `/root/all-things-ai/skills/<skill>/SKILL.md` on the VM. The app no longer relies on provider-specific skill copies.

## Setup

### Prerequisites

- Python 3.12+ with `starlette` and `uvicorn`
- Claude Code CLI (`claude`) — install via `environment/003_install-claude-code.sh`
- Codex CLI (`codex`) — install via `environment/010_install-codex.sh`
- GitHub Copilot CLI (`copilot`) — install via `environment/008_install-copilot-cli.sh`
- OpenCode CLI (`opencode`) — install via `environment/011_install-opencode.sh`
- At least one agent authenticated (`claude auth login`, `codex login`, `copilot login`, or `opencode auth login`)

### Running

```bash
# Directly
./start.sh

# Via systemd
sudo cp ctf-solver.service /etc/systemd/system/
sudo systemctl enable --now ctf-solver
```

The app starts on `https://0.0.0.0:8080` with a self-signed TLS certificate. The password is printed to stdout on first run and stored in `/root/.ctf-solver-password`.

## Features

### Agent Support

Supported providers:

| Provider | Command shape | Output mode | Model examples |
|---|---|---|---|
| Claude Code | `claude -p --dangerously-skip-permissions` | `stream-json` | Hardcoded list: Provider default, Opus, Sonnet, Haiku |
| Codex | `codex exec --json --dangerously-bypass-approvals-and-sandbox` | raw JSON events | Provider default plus models from local Codex cache/config |
| GitHub Copilot CLI | `copilot -p --yolo` | `json` | Hardcoded curated GPT/Claude/Gemini list |
| OpenCode | `opencode run --format json` | raw JSON events | Discovered dynamically from `opencode models` |

The backend keeps challenge creation, retry, stop, and steer behavior consistent across providers while mapping each CLI's native event stream into the same UI model.

For Claude, the model dropdown is now a fixed list (`Provider default`, `opus`, `sonnet`, `haiku`) and includes an optional effort selector (`low`, `medium`, `high`, `max`).

For Codex, the model dropdown is populated from `~/.codex/models_cache.json` and `~/.codex/config.toml`, so the UI reflects the machine's cached Codex model catalog and configured default. Codex also exposes an effort selector and maps it to `-c model_reasoning_effort="..."` when launching `codex exec`.

Codex effort forwarding is compatibility-guarded: if a model/effort combination is not supported by the local Codex model cache, the backend omits the effort override and falls back to provider defaults instead of failing the run.

For OpenCode, the model dropdown is populated from the machine's configured providers by running `opencode models`. If discovery fails, the UI falls back to `Provider default` and the backend omits `--model`, letting OpenCode use its own configured default.

For Copilot, the model dropdown is now a fixed curated list to avoid probe/login dependency during UI load.

The effort dropdown appears only for providers that this integration can map directly to CLI effort controls (currently Claude and Codex). Copilot and OpenCode continue to use provider defaults.

### Default Agent Toggle

A persistent toggle in the dashboard header sets the default agent for new challenges. The setting is stored in `challenges/settings.json` and pre-selects the agent dropdown when creating a challenge. Each challenge can still override the agent choice individually.

### Challenge Lifecycle

1. **Create** — Name, description, flag format, agent/model selection, file upload
2. **Solve** — Agent runs automatically on creation. Retry button available on failure.
3. **Steer** — Send guidance to a running agent. Stops the current process, then resumes the provider session with your message.
4. **Stop** — Terminate the agent process mid-solve.
5. **Delete** — Remove challenge and all associated files.

### Autonomous Mode

A checkbox (default on for Copilot) that appends instructions telling the agent to keep trying different approaches without stopping to ask for guidance.

### Real-time Activity Stream

- WebSocket-based live streaming of agent output
- Structured rendering of thinking blocks, text, tool calls, and results
- Collapsible tool details with input/output display
- Subagent tabs for parallel agent work
- Auto-scroll with manual override
- Markdown rendering with syntax-highlighted code blocks
- Copy buttons on code blocks and tool outputs

### Flag Detection

Automatically scans agent output for flag patterns (`flag{...}`, `CTF{...}`, `HTB{...}`, `picoCTF{...}`, and custom formats). Displays a banner with copy button when a flag is found.

### File Browser

- Lists all files in the challenge directory (auto-refreshes every 8s)
- Inline viewer for images, text files (with syntax highlighting), and binary files (hexdump)
- Download button for any file

### Usage Page

Accessible via the "Usage" button in the dashboard header. Shows per-agent stats:

- **Claude** — Auth info (email, plan, org), total sessions/messages, token usage by model (from `~/.claude/stats-cache.json`), daily activity bar chart
- **Codex** — Auth status inferred from `~/.codex/auth.json`, cached auth method, stored session count
- **Copilot** — Auth info (GitHub user, host, default model from `~/.copilot/config.json`), session count
- **OpenCode** — Auth status inferred from `~/.local/share/opencode/auth.json`, configured providers, stored project count
- **Challenges** — Per-agent totals: challenges attempted, solved, failed, average and total duration

### Other Features

- **Timer and cost tracking** — Elapsed time counter and token/cost display in the header
- **Export** — Download a markdown report of the agent's activity
- **Keyboard shortcuts** — `Esc` (back/close), `/` (focus steer input), `1`/`2`/`3` (sidebar tabs)
- **Toast notifications** — Solve/fail alerts when viewing a different challenge
- **Responsive layout** — Collapsible sidebar on mobile
- **Session persistence** — Challenges survive app restarts (metadata + output log stored on disk)

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/login` | Authenticate with password |
| POST | `/api/logout` | Clear session |
| GET | `/api/usage` | Agent auth status and usage stats |
| GET | `/api/settings` | Get global settings |
| PUT | `/api/settings` | Update global settings (default agent) |
| GET | `/api/challenges` | List all challenges |
| POST | `/api/challenges` | Create challenge (multipart form) |
| POST | `/api/challenges/{id}/solve` | Retry solving |
| POST | `/api/challenges/{id}/stop` | Stop agent |
| POST | `/api/challenges/{id}/steer` | Send guidance message |
| DELETE | `/api/challenges/{id}` | Delete challenge |
| GET | `/api/challenges/{id}/files` | List challenge files |
| GET | `/api/challenges/{id}/files/{path}` | View file content |
| GET | `/api/challenges/{id}/download/{path}` | Download file |
| WS | `/ws/{id}` | Real-time agent output stream |
