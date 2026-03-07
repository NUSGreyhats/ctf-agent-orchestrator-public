# CTF Solver Web App

A web application that uses AI coding agents (Claude Code and GitHub Copilot CLI) to solve CTF challenges. Upload challenge files, describe the problem, and watch an agent work through it in real time.

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

The backend spawns agent CLI processes (`claude` or `copilot`) in non-interactive mode, streams their JSONL output over WebSocket to the browser, and persists challenge state to disk.

## Setup

### Prerequisites

- Python 3.12+ with `starlette` and `uvicorn`
- Claude Code CLI (`claude`) — install via `environment/003_install-claude-code.sh`
- GitHub Copilot CLI (`copilot`) — install via `environment/008_install-copilot-cli.sh`
- At least one agent authenticated (`claude auth login` / `copilot login`)

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

Both agents are fully supported with identical workflows:

| Feature | Claude Code | Copilot CLI |
|---|---|---|
| Command | `claude -p --dangerously-skip-permissions` | `copilot -p --yolo` |
| Output format | `--output-format stream-json` | `--output-format json` |
| Model selection | opus, sonnet, haiku | Claude, GPT, Gemini variants |
| Continue/steer | `--continue` | `--continue` |
| Skills | CTF methodology + domain skills | Same (shared skill system) |

### Default Agent Toggle

A persistent toggle in the dashboard header sets the default agent (Claude or Copilot) for new challenges. The setting is stored in `challenges/settings.json` and pre-selects the agent dropdown when creating a challenge. Each challenge can still override the agent choice individually.

### Challenge Lifecycle

1. **Create** — Name, description, flag format, agent/model selection, file upload
2. **Solve** — Agent runs automatically on creation. Retry button available on failure.
3. **Steer** — Send guidance to a running agent. Stops the current process, then resumes with `--continue` and your message.
4. **Stop** — Terminate the agent process mid-solve.
5. **Delete** — Remove challenge and all associated files.

### Autonomous Mode

A checkbox (default on for Copilot) that appends instructions telling the agent to keep trying different approaches without stopping to ask for guidance. Useful for Copilot's per-request billing model where you want the agent to finish in a single run.

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
- **Copilot** — Auth info (GitHub user, host, default model from `~/.copilot/config.json`), session count
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
