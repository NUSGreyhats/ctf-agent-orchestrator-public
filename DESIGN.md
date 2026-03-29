# Design: Challenge Solving Workflow

## Solving Modes

### Single

One agent works on the challenge. Simple, no coordination.

### Parallel

Multiple agents work on the same challenge simultaneously. Each agent
works independently in its own isolated directory, maintains its own
working notes, and shares validated breakthroughs with teammates.

When any agent solves the challenge, all others are automatically
stopped.

## Agent Collaboration Model

In parallel mode, agents collaborate through shared files rather than
a centralized manager. No agent is interrupted — they pull context
when they need it.

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

### BREAKTHROUGHS.md

A shared file at `_shared/BREAKTHROUGHS.md`. Agents append to it ONLY
when they have a significant, validated finding — something confirmed
to work (e.g., found the vulnerability, extracted a key, decoded the
flag format). Hypotheses and unverified findings do NOT go here.

### How agents discover teammates' findings

1. **Prompt instruction**: Agents are told their teammates' notes exist
   and where to find them, but are told to try their own approaches
   first. They only read teammates' notes when stuck.

2. **PostToolUse hooks** (Claude and Codex): A shell script runs after
   every tool call, checks if `BREAKTHROUGHS.md` has new content since
   last check, and injects a one-line notification if so. The agent
   gets the message at a natural pause between tool calls — no
   interruption.

3. **Prompt fallback** (Copilot, OpenCode): The prompt tells agents to
   check `_shared/BREAKTHROUGHS.md` periodically when between
   approaches.

### File system layout (parallel mode)

```
challenges/{id}/
  _files/                        # Original challenge files
  _shared/
    BREAKTHROUGHS.md             # Shared breakthroughs
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

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `default_agent` | claude | Default agent for new challenges |
| `default_flag_format` | | Default flag format |
| `theme` | dark | UI theme |
| `auto_submit_flags` | false | Auto-submit detected flags to CTF platform |
