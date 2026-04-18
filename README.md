# ctf-agent-wrapper

An AI-powered CTF solving workstation. Provisions a cloud VM pre-loaded with forensics, reverse engineering, and analysis tools, then lets you throw CTF challenges at multiple AI agents via a web UI. Supports Claude Code, Codex, GitHub Copilot CLI, and OpenCode — individually or racing in parallel.

## Methodology

Modern AI agents can solve many CTF challenges autonomously — given the right tools and enough room to work. The bottleneck is usually environment, not intelligence: the agent needs binutils, forensics suites, disassemblers, and network tools installed and working, in a sandbox where it can run freely without risk.

This project streamlines that setup. It provisions an isolated cloud VM with all the tooling pre-installed, then exposes it to one or more AI agents that can execute commands, read and write files, and iterate until they find the flag.

Out of the box, agents are already effective. But we can do better by providing **skills** — structured workflows that guide how the agent should approach different challenge types (forensics, reversing, crypto, etc.). Skills act as a feedback loop: when you notice the agent going down a rabbithole or missing an obvious technique, you encode that knowledge into a skill so it doesn't repeat the mistake. Over time, the skill library compounds and the solve rate improves.

Skills live in `skills/` and are read by agents directly from `/root/ctf-agent-wrapper/skills/` on the VM.

## Supported Agents

| Agent | Models | Effort levels | Session resume | Subagent tabs | Steering |
|-------|--------|---------------|----------------|---------------|----------|
| Claude Code | Opus 4.7/4.6/4.5, Sonnet 4.6/4.5, Haiku 4.5 | Low, Medium, High, Max | Yes | Yes | Yes |
| Codex | Discovered from local cache/config | Per-model (discovered) | Yes | Partial | Yes |
| GitHub Copilot CLI | Curated GPT/Claude/Gemini list | Low, Medium, High, XHigh | No | Yes | Yes |
| OpenCode | Discovered from `opencode models` | Provider default | Yes | Partial | Yes |

All four agents run via their respective SDKs. Multiple agents can race the same challenge simultaneously using **All (parallel)** mode.

## Features

### Web UI

- **Live streaming** — Agent output streams in real time over WebSocket. Thinking blocks, tool calls, tool results, and text are rendered with syntax highlighting and collapsible sections.
- **Subagent tabs** — When an agent spawns parallel workers, each gets its own tab with independent output and status badges.
- **Flag detection** — Flags matching known patterns (`flag{...}`, `CTF{...}`, `HTB{...}`, `picoCTF{...}`, or custom formats) are automatically detected and surfaced in the sidebar. Flags show as neutral until submitted — green for correct, red for rejected. State persists across page navigations.
- **Steering** — Send guidance to a running agent mid-solve. The agent receives your message and adjusts its approach without restarting.
- **Resume & Retry** — Resume continues from the last session (preserving conversation history and session state for true context continuity). Retry starts fresh.
- **File browser** — Browse and view challenge files inline (images, text with syntax highlighting, hex view for binaries).
- **Usage tracking** — Per-agent usage dashboards with OAuth-based API data (5h/weekly utilization, per-model breakdowns, extra usage credits) shown as progress bars.
- **Toast notifications** — Flag discoveries and status changes broadcast globally via a dedicated WebSocket, so you get notified even when viewing a different challenge.
- **Export** — Export challenge reports as markdown with full activity logs.

### Challenge Management

- **Single challenges** — Create with name, description, flag format, and file uploads.
- **Bulk upload** — Upload `.zip` or `.7z` archives with one folder per challenge. Preview and edit metadata before importing.
- **Platform import** — Fetch challenges directly from CTFd or rCTF instances. Saves connections for future syncs with automatic points/solves updates.
- **Auto-submit** — Detected flags can be automatically submitted to the connected CTF platform.

### Parallel Mode & Collaboration

When multiple agents solve the same challenge, each gets an isolated working directory with symlinked challenge files and a shared workspace.

- **Working notes** — Each agent maintains `WORKING_NOTES_{agent}.md`. Cross-symlinks let every agent read its teammates' notes.
- **Teammate notifications** — Agents can call the `notify_teammates` MCP tool to broadcast breakthroughs. A background poller injects these messages into teammates' sessions every 5 seconds.
- **Auto-stop on solve** — When one agent finds the flag, all other agents are automatically stopped.

### Infrastructure

- **GDB MCP server** — Persistent GDB session for kernel/binary debugging, registered for Claude, Codex, and OpenCode.
- **WireGuard VPN** — Built-in VPN management for challenges that require network access to a CTF infrastructure. Configure, start/stop, and generate client configs from the web UI.
- **Skills library** — Methodology, forensics (disk/file/memory/network), tool-specific (IDA, APK, kernel-GEF, libdebug), and community skills (crypto, pwn, reverse, web, misc, osint, malware).

### Persistence

All state survives server restarts:
- Challenge metadata, run history, and detected flags persist to `/root/.ctf-solver-state/`.
- Output logs persist as JSONL files per run.
- Stale "solving" runs are automatically reset to "failed" on server restart.
- Platform connections and settings persist to disk.

## How to Use

### 1. Deploy the VM

Two cloud providers are supported (Hetzner and DigitalOcean). Pick one — see [infra/README.md](infra/README.md) for details.

```bash
cd infra/hetzner   # or infra/digitalocean
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your settings, then:

```bash
terraform init
terraform plan
terraform apply
```

This creates a VM and runs all setup scripts. When it finishes, Terraform prints the web app URL and password.

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
copilot login          # GitHub Copilot CLI
opencode auth login    # OpenCode
```

### 3. Solve Challenges

#### Option A: Web UI

Open `https://<VM_IP>` in your browser and log in.

1. Click **+ New Challenge** (or **Bulk Upload**, or import from a CTF platform)
2. Fill in the name, description, flag format, and upload challenge files
3. Select an agent or choose **All (parallel)** to race multiple agents
4. Click **Create & Solve** and watch the agent work in real time
5. Steer the agent if it gets stuck, or Resume/Retry if it finishes without solving

#### Option B: Terminal

Upload challenges and use an agent directly:

```bash
scp -r ./my-ctf-challenges root@<VM_IP>:/root/challenges/
ssh root@<VM_IP>

# Claude Code
cd /root/challenges && yolo

# Codex
cd /root/challenges && codex --dangerously-bypass-approvals-and-sandbox

# Copilot CLI
cd /root/challenges && copilot --yolo

# OpenCode
cd /root/challenges && opencode
```

### Teardown

```bash
cd infra/hetzner   # or infra/digitalocean
terraform destroy
```

## Project Structure

```
infra/          Terraform configs (Hetzner Cloud and DigitalOcean)
environment/    Setup scripts (tools, CLIs, dependencies)
webapp/         Web app (Starlette/ASGI) for challenge management and agent streaming
  agents/       Agent provider implementations (Claude, Codex, Copilot, OpenCode)
  plugins/      CTF platform integrations (CTFd, rCTF)
  static/       Frontend (vanilla JS, CSS)
skills/         Agent skills (methodology, forensics, tool-specific, community)
mcps/           MCP servers (GDB debugger)
```
