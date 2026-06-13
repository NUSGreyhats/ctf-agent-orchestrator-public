# ctf-agent-orchestrator

An AI-powered CTF solving workstation. It provisions a cloud VM pre-loaded with reverse-engineering, forensics, crypto, pwn, and web tooling, then lets you throw CTF challenges at one or more AI agents — **Claude Code** and **Codex** — through a web UI. Run a single agent, race several in parallel, or fan challenges out to a fleet of disposable worker VMs.

```
┌──────────┐   challenge    ┌─────────────────────┐   spawns    ┌──────────────┐
│ Web UI / │ ─────────────► │  Webapp (Starlette) │ ──────────► │ Claude / Codex│
│ Discord  │ ◄───────────── │  state · streaming  │ ◄────────── │ + full toolkit│
└──────────┘   live stream  └─────────────────────┘   events    └──────────────┘
```

## Why

Modern AI agents can solve many CTF challenges autonomously — the bottleneck is usually *environment*, not intelligence. An agent needs binutils, disassemblers, debuggers, forensics suites, network tools, and a sandbox where it can run freely. This project provisions that environment once, then exposes challenges to agents that can execute commands, read/write files, collaborate, and iterate until they find the flag.

Agents are effective out of the box, but get better with **skills** — structured, version-controlled workflows that guide how to approach each challenge type (forensics, reversing, crypto, pwn, web, …). When you catch an agent down a rabbit hole or missing an obvious technique, you encode that lesson into a skill so it doesn't repeat the mistake. The skill library compounds over time and the solve rate climbs.

## Features

**Agents & solving**
- **Claude Code and Codex**, via their native SDK/integration paths. Pick model and reasoning effort per agent.
- **Parallel mode** — add multiple agent rows to race the same challenge. Each agent gets an isolated workspace and shares validated breakthroughs through working notes and the `notify_teammates` tool.
- **Steering** — send mid-solve guidance; the agent resumes from its current session with your message.
- **Resume / Retry / Solve / Unsolve** — resume from saved session state, restart fresh, or manually override status.
- **Advisor** — a per-challenge conversational agent that reads the solvers' live transcripts, answers your questions, researches techniques/CVEs online, and can relay concise hints to the running solvers.

**Web UI**
- **Live streaming** over WebSocket — thinking blocks, tool calls, results, and text with syntax highlighting and collapsible sections; split or tabbed views for parallel runs.
- **Flag detection** — auto-detects `flag{…}`, `CTF{…}`, `HTB{…}`, `picoCTF{…}`, and custom formats. A silent `ctfgrep` preflight over challenge files surfaces candidate flags before the agent even starts.
- **Auto-submit** — detected flags can be submitted to the connected platform; a correct flag marks the challenge solved and stops sibling runs.
- **File browser** — inspect original challenge files and per-run workspaces (images, syntax-highlighted text, hex for binaries).
- **Usage & statistics** — per-agent account/usage dashboards and per-challenge token/cost/duration/turn breakdowns.
- **Export** — download a markdown report with the full activity log.

**Challenge management**
- **Single, bulk (`.zip`/`.7z`), and platform import.** Pull challenges directly from **CTFd, rCTF, Hack The Box CTF, CDDC, Cywaria/Cympire, and SAS CTF**; saved connections re-sync for new challenges, points, and solves.
- **On-demand instances** — HTB, Cywaria, and SAS CTF challenges with Docker/machine instances are started at solve time and their connection info is injected into the prompt.
- **Per-challenge / per-run skills** — set global defaults, lock challenge-level skills at creation, or change a run's skills mid-solve (symlinks refresh and the agent resumes).
- **TLS verification on by default**, with an explicit opt-out for self-signed/local events.

**Infrastructure**
- **One-command deploy** via Terraform to **Hetzner Cloud, DigitalOcean, or GCP**.
- **Swarm** — dispatch a challenge to a dedicated, disposable GCP worker VM cloned from a golden image, isolating heavy CPU/RAM/disk work from the controller. See [SWARM.md](SWARM.md).
- **WireGuard VPN** — built-in management for challenges that need network access to CTF infrastructure, with reverse routing to client-side internal CIDRs.
- **Integrated tooling** — a persistent GDB MCP server (Claude + Codex) and headless IDA Pro analysis via the `analyze-with-ida-domain-api` skill.
- **Discord bot** (optional) — per-challenge threads/channels, real-time notifications, flag review, and slash commands for team coordination.

> For internals — collaboration model, filesystem layout, solve lifecycle, security model, persistence, and settings reference — see **[DESIGN.md](DESIGN.md)**.

## Supported Agents

| Agent | Models | Effort levels | Resume | Collaboration | Steering |
|-------|--------|---------------|--------|---------------|----------|
| **Claude Code** | Provider default, Fable 5, Opus 4.8/4.7/4.6/4.5, Sonnet 4.6/4.5, Haiku 4.5 (default **Opus 4.6 1M**) | Provider default, Low, Medium, High, Max (default **High**) | ✅ | `notify_teammates`, working notes | ✅ |
| **Codex** | Discovered from local Codex cache/config | Per-model; common fallback Low, Medium, High, XHigh (default **XHigh**) | ✅ | `notify_teammates`, working notes | ✅ |

Two or more agent rows on a challenge automatically create a parallel run.

## Getting Started

### 1. Deploy the VM

Pick a cloud provider (see [infra/README.md](infra/README.md) for provider-specific options):

```bash
cd infra/hetzner          # or infra/digitalocean or infra/gcp
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your settings

terraform init
terraform apply
```

This creates the VM, copies runtime files, runs the setup scripts, validates the environment, and starts the webapp service. Retrieve the login password with:

```bash
terraform output -raw webapp_password   # also stored on the VM at /root/.ctf-solver-password
```

### 2. Authenticate the agents

SSH in and log in to whichever agents you'll use:

```bash
ssh root@$(terraform output -raw external_ip)
claude auth login      # Claude Code
codex login            # Codex
```

### 3. Solve from the web UI

Open `https://<VM_IP>` and log in, then:

1. **+ Add Challenge** → Single, Bulk Upload, or Import from Platform.
2. Fill in name, description, flag format, and upload/import files.
3. Pick agent / model / effort — add more rows to race in parallel.
4. **Create & Solve** and watch output stream live.
5. Steer if it stalls; Resume/Retry if it finishes unsolved; use the Files tab to inspect workspaces.

### 4. (Optional) Discord

Enable Discord in **Settings** with a bot token and channel. The bot creates per-challenge threads/channels and supports slash commands — `/ctf`, `/status`, `/flags`, `/files`, `/broadcast`, `/submit`, `/solved`, `/resume`, `/stop`.

### Teardown

```bash
cd infra/hetzner   # or your provider
terraform destroy
```

## Skills

Skills are structured workflows that steer how agents approach challenge types. They come from two sources, both compiled into the runtime `all-skills/` catalog during setup:

- **This repo** (`skills/`) — CTF methodology, forensics (disk, memory, pcap, stego/repair), and tool-specific skills (IDA, apk analysis, kernel GEF debugging, angrop ROP chains).
- **[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)** — category skills for pwn, web, crypto, rev, misc, osint, malware, and AI/ML.

The webapp symlinks selected skills into each run's `.claude/skills` and `.codex/skills`. You can also upload a `.zip` bundle or single `SKILL.md` from **Settings**. See [skills/README.md](skills/README.md) for the full catalog.

## Project Structure

```text
infra/            Terraform configs (Hetzner, DigitalOcean, GCP)
install_scripts/  Numbered provisioning scripts (tools, CLIs, deps); run.sh, lib/ helpers
webapp/           Starlette/ASGI app — challenge management + agent streaming
  agents/         Agent provider implementations (Claude, Codex) + broadcast bus
  plugins/        CTF platform integrations (CTFd, rCTF, HTB, CDDC, Cywaria, SAS)
  swarm*.py       Remote GCP worker dispatch (manager, runner, exec)
  static/         Frontend (vanilla JS, CSS)
mcps/             MCP servers (GDB debugger)
skills/           Repo-owned agent skills (methodology, forensics, tools)
```

Runtime-only directories created on the VM: `all-skills/` (compiled skill catalog), `challenges/` (uploaded files, workspaces, settings), and `state/` (challenge metadata, per-run JSONL logs, platform connections). These are preserved across deploy syncs.

## Documentation

- **[DESIGN.md](DESIGN.md)** — architecture, collaboration model, filesystem layout, solve lifecycle, platform plugins, VPN, security, persistence, and the full settings reference.
- **[SWARM.md](SWARM.md)** — remote GCP execution design and operations.
- **[infra/README.md](infra/README.md)** — per-provider Terraform usage.
- **[skills/README.md](skills/README.md)** — skill catalog.
</content>
</invoke>
