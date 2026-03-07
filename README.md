# all-things-ai

An AI-powered CTF solving workstation. Spins up a GCP VM pre-loaded with forensics, reverse engineering, and analysis tools, then lets you throw CTF challenges at Claude Code or GitHub Copilot CLI agents via a web UI or the terminal.

## Methodology

Modern AI agents are capable of solving many CTF challenges autonomously — given the right tools and enough room to work. The bottleneck is usually environment, not intelligence: the agent needs binutils, forensics suites, disassemblers, and network tools installed and working, in a sandbox where it can run freely without risk.

This project streamlines that setup. It provisions an isolated cloud VM with all the tooling pre-installed, then exposes it to one or more AI agents that can execute commands, read and write files, and iterate until they find the flag.

Out of the box, agents are already effective. But we can do better by providing **skills** — structured workflows that suggest or enforce how the agent should approach different challenge types (forensics, reversing, crypto, etc.). Skills act as a feedback loop: when you notice the agent going down a rabbithole or missing an obvious technique, you encode that knowledge into a skill so it doesn't repeat the mistake. Over time, the skill library compounds and the solve rate improves.

Skills live in the `skills/` directory and are loaded automatically by both Claude Code and Copilot CLI.

## Supported Agents

| Agent | Models | Subagent tabs | Steering |
|-------|--------|---------------|----------|
| Claude Code | Opus, Sonnet, Haiku | Yes | Yes |
| GitHub Copilot CLI | Claude, GPT, Gemini | Yes | Yes |

Both agents can be run on the same challenge simultaneously using the **Both (parallel)** option.

## How to Use

### 1. Deploy the VM

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your GCP project ID, then:

```bash
gcloud auth application-default login
terraform init
terraform plan
terraform apply
```

This creates a VM and runs all environment setup scripts (tool installation, agent CLIs, web app). Takes around 15 minutes on `e2-standard-4`.

When it finishes, Terraform prints the web app URL and password.

### 2. Authenticate the Agents

SSH into the VM:

```bash
ssh root@$(cd infra && terraform output -raw external_ip)
```

Authenticate whichever agents you want to use:

```bash
# Claude Code
claude auth login

# GitHub Copilot CLI
copilot login
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

# Copilot CLI
cd /root/challenges
copilot --yolo
```

Tell the agent to spawn subagents to solve each challenge directory concurrently.

#### Option B: Web UI

Open `https://<VM_IP>:8080` in your browser and log in with the password from the Terraform output (also stored in `/root/.ctf-solver-password`).

1. Set your default agent (Claude or Copilot) using the toggle in the header
2. Click **+ New Challenge**
3. Fill in the name, description, flag format, and upload the challenge files
4. Select the agent — Claude, Copilot, or **Both (parallel)** to race them side by side
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
infra/          Terraform config for GCP VM provisioning
environment/    Setup scripts (tools, CLIs, dependencies)
webapp/         Web app for challenge management and agent streaming
skills/         Agent skills (CTF methodology, domain-specific)
```

See [webapp/README.md](webapp/README.md) for detailed web app documentation.
