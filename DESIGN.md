# Design: Challenge Solving Workflow

## Solving Modes

### Single

One agent works on the challenge. Simple, no coordination.

### Parallel

Multiple agents work on the same challenge simultaneously. Each agent
works independently in its own isolated directory, maintains its own
working notes, and shares validated breakthroughs with teammates via
the `notify_teammates` tool.

When any agent solves the challenge, all others are automatically
stopped.

## Agent Collaboration Model

In parallel mode, agents collaborate through a `notify_teammates` tool
registered via each provider's SDK, plus shared working notes files.

### WORKING_NOTES_{agent}.md

Each agent maintains a structured notes file:

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

Agents update this file continuously. It serves as persistent memory
that survives context compaction and as a reference for teammates.

### notify_teammates Tool

Each provider registers a `notify_teammates` tool via its native SDK:

- **Claude**: In-process MCP tool via `create_sdk_mcp_server`
- **Codex**: Dynamic tool via `thread/start` `dynamicTools`
- **Copilot**: `define_tool` with Python handler
- **OpenCode**: TypeScript tool file in `.opencode/tools/`

When an agent calls `notify_teammates("found UAF in handler X")`:
1. The tool handler puts the message into an in-memory broadcast queue
2. After the current turn completes, other agents receive the message
   as their next turn input via SDK session messaging
3. No interruption — delivery at natural turn boundaries

### How agents discover teammates' findings

1. **notify_teammates tool**: Agents call it for validated breakthroughs.
   Teammates receive the message between turns automatically.

2. **Working notes symlinks**: Each run directory has symlinks to other
   agents' WORKING_NOTES files. The prompt tells agents to read these
   when stuck.

### File system layout (parallel mode)

```
challenges/{id}/
  _files/                        # Original challenge files
  _shared/                       # Shared directory
  _runs/
    {run_id_1}/                  # Agent A's workspace
      challenge_file.bin -> ../../_files/challenge_file.bin
      _shared/ -> ../../_shared/
      WORKING_NOTES_claude.md    # Agent A's notes
      WORKING_NOTES_codex.md -> ../{run_id_2}/WORKING_NOTES_codex.md
    {run_id_2}/                  # Agent B's workspace
      challenge_file.bin -> ../../_files/challenge_file.bin
      _shared/ -> ../../_shared/
      WORKING_NOTES_codex.md     # Agent B's notes
      WORKING_NOTES_claude.md -> ../{run_id_1}/WORKING_NOTES_claude.md
```

## SDK Integration

All 4 providers use their respective SDKs instead of CLI subprocesses:

| Provider | SDK | Protocol |
|----------|-----|----------|
| Claude | `claude-agent-sdk` | Native Python, typed messages |
| Codex | `codex app-server` | JSON-RPC 2.0 over stdio |
| Copilot | `github-copilot-sdk` | Python SDK with event callbacks |
| OpenCode | `opencode-sdk` | REST API to `opencode serve` |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `default_agent` | claude | Default agent for new challenges |
| `default_flag_format` | | Default flag format |
| `theme` | dark | UI theme |
| `auto_submit_flags` | false | Auto-submit detected flags to CTF platform |
