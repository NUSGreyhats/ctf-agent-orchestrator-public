# all-things-ai

An AI-powered CTF solving workstation. Spins up a Hetzner Cloud VM pre-loaded with forensics, reverse engineering, and analysis tools, then lets you throw CTF challenges at Claude Code, Codex, GitHub Copilot CLI, or OpenCode agents via a web UI or the terminal.

## Methodology

Modern AI agents are capable of solving many CTF challenges autonomously — given the right tools and enough room to work. The bottleneck is usually environment, not intelligence: the agent needs binutils, forensics suites, disassemblers, and network tools installed and working, in a sandbox where it can run freely without risk.

This project streamlines that setup. It provisions an isolated cloud VM with all the tooling pre-installed, then exposes it to one or more AI agents that can execute commands, read and write files, and iterate until they find the flag.

Out of the box, agents are already effective. But we can do better by providing **skills** — structured workflows that suggest or enforce how the agent should approach different challenge types (forensics, reversing, crypto, etc.). Skills act as a feedback loop: when you notice the agent going down a rabbithole or missing an obvious technique, you encode that knowledge into a skill so it doesn't repeat the mistake. Over time, the skill library compounds and the solve rate improves.

Skills live in the `skills/` directory, and `/root/all-things-ai/skills/` on the VM is the source of truth for every provider. The web app prompt tells agents to read the relevant `SKILL.md` files directly from that repo path.

Kernel debugging via the local GDB MCP server (`/root/all-things-ai/mcps/gdb_mcp.py`) is provisioned during environment setup and registered for Claude Code, Codex, and OpenCode.

## Supported Agents

| Agent | Models | Subagent tabs | Steering |
|-------|--------|---------------|----------|
| Claude Code | Hardcoded list (`Provider default`, `opus`, `sonnet`, `haiku`) | Yes | Yes |
| Codex | Discovered from local Codex cache/config (with effort selector) | Partial | Yes |
| GitHub Copilot CLI | Hardcoded curated GPT/Claude/Gemini list | Yes | Yes |
| OpenCode | Discovered from `opencode models` | Partial | Yes |

Multiple agents can be run on the same challenge simultaneously using the **All (parallel)** option.

Effort selection in the web UI is currently exposed for Claude and Codex. Copilot and OpenCode run with provider-default reasoning settings in this wrapper.

## How to Use

### 1. Deploy the VM

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your Hetzner Cloud settings, then:

```bash
terraform init
terraform plan
terraform apply
```

This creates a VM and runs all environment setup scripts (tool installation, agent CLIs, web app).

When it finishes, Terraform prints the web app URL and password.

You can retrieve the password again later with:

```bash
cd infra
terraform output -raw webapp_password
```

### 2. Authenticate the Agents

SSH into the VM:

```bash
ssh root@$(cd infra && terraform output -raw external_ip)
```

Authenticate whichever agents you want to use:

```bash
# Claude Code
claude auth login

# Codex
codex login

# GitHub Copilot CLI
copilot login

# OpenCode
opencode auth login
```

### 3. Solve Challenges

You have two options:

#### Option A: Terminal (batch)

Upload a directory of challenges to the VM (one challenge per subdirectory):

```bash
scp -r ./my-ctf-challenges root@<VM_IP>:/root/challenges/
```

Then SSH in and use an agent to solve them in parallel:

```bash
# Claude Code
cd /root/challenges
yolo  # alias for: IS_SANDBOX=1 claude --dangerously-skip-permissions

# Codex
cd /root/challenges
codex --dangerously-bypass-approvals-and-sandbox

# Copilot CLI
cd /root/challenges
copilot --yolo

# OpenCode
cd /root/challenges
opencode
```

Tell the agent to spawn subagents to solve each challenge directory concurrently.

#### Option B: Web UI

Open `https://<VM_IP>:8080` in your browser and log in with the password from the Terraform output (also stored in `/root/.ctf-solver-password`).

1. Set your default agent using the toggle in the header
2. Click **+ New Challenge**
3. Fill in the name, description, flag format, and upload the challenge files
4. Select the agent or choose **All (parallel)** to race multiple providers side by side
5. Click **Create & Solve** and watch the agent work in real time

**Bulk upload:** Click **Bulk Upload** to upload a zip file containing multiple challenges (one folder per challenge, with an optional `description.txt` in each). All challenges start solving automatically.

The web UI streams agent output live, shows subagent tabs when agents spawn parallel workers, detects flags automatically (shown in the sidebar), and lets you steer the agent mid-solve if it gets stuck.

### Teardown

```bash
cd infra
terraform destroy
```

## Project Structure

```
infra/          Terraform config for Hetzner Cloud provisioning
environment/    Setup scripts (tools, CLIs, dependencies)
webapp/         Web app for challenge management and agent streaming
skills/         Agent skills (CTF methodology, domain-specific)
```

See [webapp/README.md](webapp/README.md) for detailed web app documentation.
