# ctf-agent-wrapper

An AI-powered CTF solving workstation. It provisions a cloud VM pre-loaded with forensics, reverse engineering, debugging, and analysis tools, then lets you throw CTF challenges at one or more AI agents via a web UI. Supports Claude Code and Codex — individually or racing in parallel.

## Methodology

Modern AI agents can solve many CTF challenges autonomously — given the right tools and enough room to work. The bottleneck is usually environment, not intelligence: the agent needs binutils, forensics suites, disassemblers, debuggers, network tools, and a sandbox where it can run freely.

This project streamlines that setup. It provisions an isolated cloud VM with the tooling pre-installed, then exposes challenges to agents that can execute commands, read and write files, collaborate, and iterate until they find the flag.

Out of the box, agents are already effective. But we can do better by providing **skills** — structured workflows that guide how the agent should approach different challenge types (forensics, reversing, crypto, pwn, web, etc.). Skills act as a feedback loop: when you notice an agent going down a rabbithole or missing an obvious technique, you encode that knowledge into a skill so it does not repeat the mistake. Over time, the skill library compounds and the solve rate improves.

Repo-owned skills live in `skills/`. During install-script setup, repo-owned and external skills are copied into the generated `all-skills/` catalog. The web app then symlinks the selected skills into each challenge run's project-level agent skill directories, such as `.claude/skills` and `.codex/skills`; Codex runs also receive the selected `.codex/skills` entries as structured skill inputs. Additional skills can be uploaded from Settings as a `.zip` bundle or single `SKILL.md`, and are installed into the same runtime catalog.

## Supported Agents

| Agent | Models | Effort levels | Session resume | Collaboration | Steering |
|-------|--------|---------------|----------------|---------------|----------|
| Claude Code | Provider default, Opus 4.8/4.7/4.6/4.5, Sonnet 4.6/4.5, Haiku 4.5. Default: Opus 4.6 (1M) | Provider default, Low, Medium, High, Max | Yes | `notify_teammates`, working notes | Yes |
| Codex | Discovered from local cache/config | Per-model, discovered from local cache; common fallback includes Low, Medium, High, XHigh. Default: XHigh | Yes | Dynamic `notify_teammates`, working notes | Yes |

Both agents run through their provider integration paths. Multiple agents can race the same challenge by adding multiple agent rows when creating, bulk uploading, or importing challenges; two or more agent rows automatically create a parallel challenge.

## Features

### Web UI

- **Live streaming** — Agent output streams in real time over WebSocket. Thinking blocks, tool calls, tool results, raw output, and text are rendered with syntax highlighting and collapsible sections.
- **Per-run views** — Single challenges have one run. Parallel challenges have one run per agent and can be viewed side-by-side or as tabs.
- **Flag detection** — Flags matching known patterns (`flag{...}`, `CTF{...}`, `HTB{...}`, `picoCTF{...}`, or custom formats) are automatically detected and surfaced in the sidebar. A fresh run also performs a silent `ctfgrep` preflight over challenge files and adds bounded matches as detected flag candidates without putting scan output into the agent prompt. Flags show as neutral until submitted — green for correct, red for rejected. State persists across page navigations.
- **Steering** — Send guidance to a running agent mid-solve. The agent is stopped and resumed with your message from the current session where supported.
- **Runtime agent controls** — Stop a single active agent, stop all active agents, or add new agents to an existing unsolved challenge with a custom prompt and skill list.
- **Resume & Retry** — Resume continues from saved session state when available. Retry starts fresh. Mark Solved and Unsolve let you manually override challenge status.
- **Chat view modes** — Split view (agents side-by-side) or tabbed view (click to switch), configurable in settings.
- **File browser** — Browse challenge files and agent workspaces. Challenge files are stored separately from provider working directories; each run sees them through `./challenge_files/`. The browser can view images, text with syntax highlighting, and binaries as hex.
- **Usage tracking** — Per-agent usage dashboards with account/usage data where available. Per-challenge statistics show token counts, cost, duration, turns, and per-model breakdowns when providers emit them.
- **Toast notifications** — Flag discoveries and status changes broadcast globally via a dedicated WebSocket, so you get notified even when viewing a different challenge.
- **Export** — Export challenge reports as markdown with full activity logs.

### Challenge Management

- **Single challenges** — Create with name, description, flag format, agent/model/effort choices, and file uploads.
- **Bulk upload** — Upload `.zip` or `.7z` archives with one folder per challenge. Preview and edit metadata before importing.
- **Skills per challenge/run** — Select default skills globally, lock challenge-level skills at creation/import time, and adjust skills for individual active runs. Skill changes stop the target agent, refresh `.claude/skills` and `.codex/skills` symlinks, then resume by default.
- **Platform import** — Fetch challenges directly from CTFd, rCTF, Hack The Box CTF, CDDC, Cywaria/Cympire, or SAS CTF instances. Saves connections for future syncs with automatic points/solves updates where supported. HTB, Cywaria, and SAS CTF challenges with on-demand instances are started automatically at solve time.
- **Multi-answer HTB support** — HTB `flagsInfo` questions are injected into the agent prompt, and agents get a `submit_answer.py` helper for answer-checking when there is no fixed flag format.
- **Auto-submit** — Detected flags can be automatically submitted to the connected CTF platform. Correct submissions mark the challenge solved and stop other active runs.
- **TLS verification by default** — CTFd and rCTF verify TLS certificates by default and expose an explicit “Disable TLS certificate verification” checkbox for self-signed/local events. HTB uses normal TLS verification. SAS CTF also exposes the checkbox and defaults it on for the current event endpoint.

### Challenge File and Workspace Layout

Uploaded/imported files are treated as untrusted challenge data and kept out of the provider cwd.

New challenges use this layout for both single and parallel modes:

```text
/root/ctf-agent-wrapper/challenges/{challenge_id}/
  _files/                         # original uploaded/imported challenge files
  _runs/{run_id}/                  # provider working directory
    challenge_files/               # symlink tree pointing at ../../_files
    WORKING_NOTES.md               # single mode notes, created by agent/prompt
```

Parallel challenges additionally use:

```text
/root/ctf-agent-wrapper/challenges/{challenge_id}/
  _shared/                         # shared collaboration directory
  _runs/{run_id}/
    _shared -> ../../_shared
    WORKING_NOTES_{agent}.md
    WORKING_NOTES_{teammate}.md -> ../{teammate_run}/WORKING_NOTES_{teammate}.md
```

The prompt tells agents to use `./challenge_files/` when challenge files exist. Description-only or remote-instance challenges are explicitly handled as no-file challenges.

### Parallel Mode & Collaboration

When multiple agents solve the same challenge, each gets an isolated working directory with a symlinked `challenge_files/` data directory and, in parallel mode, access to shared notes/state.

- **Working notes** — Each parallel agent maintains `WORKING_NOTES_{agent}.md`. Cross-symlinks let every agent read teammates' notes.
- **Teammate notifications** — Agents can call the `notify_teammates` tool to broadcast validated breakthroughs. A background poller injects these messages into teammates' sessions.
- **User broadcast** — Send a message to all running agents simultaneously from the web UI or Discord.
- **Auto-stop on solve** — When one agent is marked solved or submits a correct flag, sibling runs are automatically stopped.

### Discord Integration

Optional Discord bot for team coordination:

- **Per-challenge Discord destinations** — Discord can create either a thread per challenge in the selected announcement channel, or a text channel per challenge under a Discord category matching the challenge category. Channel mode requires the bot to have Manage Channels.
- **Real-time notifications** — Solve events, flag detections, breakthroughs, starts, completions, and stops are posted to Discord.
- **Flag review** — Detected flags can be submitted, rejected, marked correct, or broadcast to active agents directly from Discord.
- **Action buttons** — Challenge messages include buttons for status, stats, tail, flags, submit flag, mark solved, stop, and resume.
- **Slash commands** — `/broadcast`, `/submit`, `/status`, `/flags`, `/stop`, `/resume`, `/solved`, `/ctf`, `/files` for controlling agents and viewing challenge state from Discord.
- **Live settings** — Enabling/disabling Discord or changing token/channel/guild settings starts, stops, or restarts the gateway without requiring a webapp restart.

### Infrastructure and Deployment

- **Cloud providers** — Terraform configs for Hetzner Cloud, DigitalOcean, and GCP.
- **Runtime allowlist deploy** — Deploys copy only runtime project files (`install_scripts`, `webapp`, `skills`, `mcps`, `README.md`, `DESIGN.md`) instead of the whole repo. Local `.git/`, `infra/`, Terraform state/vars, and local caches are not copied to the VM. Runtime `challenges`, `state`, and generated `all-skills` are preserved.
- **Runtime data preservation** — Deploy sync preserves `/root/ctf-agent-wrapper/challenges` and `/root/ctf-agent-wrapper/state` on the VM.
- **GDB MCP server** — Persistent GDB session for kernel/binary debugging, registered for Claude and Codex.
- **IDA Pro skill** — Headless static analysis through the `analyze-with-ida-domain-api` skill, backed by IDA Pro's Python Domain API.
- **WireGuard VPN** — Built-in VPN management for challenges that require network access to a CTF infrastructure. Generate ready-to-run Linux client configs, start/stop the server tunnel, and route Linux client-side internal CIDRs back to the server through a reverse WireGuard tunnel.
- **uv-based Python installs** — Install scripts install most Python dependencies with `uv pip install --system` for faster provisioning while keeping `pip` available for vendor-local wheels.
- **Parallel install setup** — `install_scripts/run.sh` runs independent tooling categories concurrently with package-manager locks; set `INSTALL_SCRIPTS_PARALLEL=0` for sequential setup.
- **Provisioning validation** — `install_scripts/990_validate.sh` checks critical commands and Python imports at the end of setup.

### Persistence

Runtime state survives server restarts and deploy syncs:

- Challenge metadata, run history, and detected flags persist under `/root/ctf-agent-wrapper/state/`.
- Output logs persist as JSONL files per run.
- Stale `solving` runs are automatically reset to `failed` on server restart.
- Platform connections persist to `/root/ctf-agent-wrapper/state/connections.json`.
- Settings persist to `/root/ctf-agent-wrapper/challenges/settings.json`.

## How to Use

### 1. Deploy the VM

Three cloud providers are supported: Hetzner, DigitalOcean, and GCP. Pick one — see [infra/README.md](infra/README.md) for details.

```bash
cd infra/hetzner   # or infra/digitalocean or infra/gcp
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your settings, then:

```bash
terraform init
terraform plan
terraform apply
```

This creates a VM, copies runtime files, runs setup scripts, validates the environment, installs/starts the webapp service, and prints the web app URL and password.

Retrieve the password later with:

```bash
cd infra/hetzner
terraform output -raw webapp_password
```

The password is also stored on the VM at `/root/.ctf-solver-password`.

### 2. Authenticate the Agents

SSH into the VM:

```bash
ssh root@$(cd infra/hetzner && terraform output -raw external_ip)
```

Authenticate whichever agents you want to use:

```bash
claude auth login      # Claude Code
codex login            # Codex
```

### 3. Solve Challenges from the Web UI

Open `https://<VM_IP>` in your browser and log in.

1. Click **+ Add Challenge** and choose **Add Single Challenge**, **Bulk Upload**, or **Import from Platform**.
2. Fill in the name, description, flag format, and upload/import challenge files.
3. Pick an agent/model/effort. Add more agent rows to run in parallel.
4. Click **Create & Solve** and watch the run output stream in real time.
5. Steer the agent if it gets stuck, or Resume/Retry if it finishes without solving.
6. Use the Files tab to inspect original challenge files or per-run workspaces.

### 4. Use the Discord Bot

Enable Discord in Settings by providing a bot token and channel. The bot creates per-challenge threads and supports slash commands for team workflows:

- `/ctf` to list or open challenge context
- `/status`, `/flags`, and `/files` to inspect progress
- `/broadcast` and `/steer` to guide active agents
- `/submit`, `/solved`, `/resume`, and `/stop` to control solving state

### Teardown

```bash
cd infra/hetzner   # or infra/digitalocean or infra/gcp
terraform destroy
```

## Project Structure

```text
infra/          Terraform configs (Hetzner Cloud, DigitalOcean, GCP)
install_scripts/ Setup scripts (tools, CLIs, dependencies)
  lib/          Shared shell helpers used by setup scripts
webapp/         Starlette/ASGI app for challenge management and agent streaming
  agents/       Agent provider implementations (Claude, Codex)
  plugins/      CTF platform integrations (CTFd, rCTF, HTB CTF, CDDC, Cywaria, SAS CTF)
  static/       Frontend (vanilla JS, CSS)
skills/         Agent skills (methodology, forensics, tool-specific, community)
all-skills/     Runtime skill catalog populated by setup and Settings uploads
mcps/           MCP servers (GDB debugger)
state/          Runtime state on the VM: metadata, output logs, connections
```
