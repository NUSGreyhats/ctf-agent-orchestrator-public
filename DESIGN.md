# Design: Challenge Solving Workflow

This document describes the four solving modes available in the CTF Solver
and how the manager agent orchestrates work across agents.

## Solving Modes

### Mode 1: Single Agent

The simplest mode. One agent works on the challenge from start to finish.
No manager, no coordination — just the agent and the challenge files.

**When to use:** Quick challenges, trusted agent, or when you want full
control via manual steering.

**Flow:**
1. User creates challenge, picks an agent and model
2. Agent receives the challenge prompt, reads the methodology skill, triages,
   and works toward the flag
3. User can manually steer the agent if it gets stuck
4. Agent either solves or fails

### Mode 2: Single Agent (Managed)

One agent at a time, but a manager agent reviews progress at fixed intervals.
If the solver is stuck, the manager can steer it with specific instructions
or hand off the challenge to a different agent entirely.

**When to use:** Harder challenges where you want automated oversight and the
ability to try multiple agents without manual intervention.

**Flow:**
1. User creates challenge, picks the starting agent
2. Agent works on the challenge and maintains a `FINDINGS.md` file documenting
   what it has tried and discovered
3. Every N minutes (configurable), the manager reviews progress:
   - **WAIT** — agent is making progress, no intervention needed
   - **STEER** — agent is stuck or missing something. Manager provides specific
     instructions (blind spots, unconventional techniques, new approaches)
   - **HANDOFF** — the issue is agent capability, not approach. Manager stops
     the current agent and starts a different one from the configured agent
     pool. The new agent reads `FINDINGS.md` to understand what has been tried
   - **SHELVE** — the challenge has been sufficiently attempted and further
     effort is unlikely to yield results. Challenge is shelved with notes
4. On handoff, the previous agent's output is summarized and the new agent
   receives both the summary and `FINDINGS.md` as context
5. This continues until the challenge is solved, shelved, or manually stopped

**FINDINGS.md:** The agent maintains this file throughout its work. It
persists across handoffs — each agent reads it on start and updates it as it
works. This is the primary knowledge transfer mechanism between agents.

### Mode 3: Parallel Agents

Multiple agents race on the same challenge simultaneously. No coordination
between them — first to solve wins.

**When to use:** When speed matters and you want to throw multiple agents at
a problem without caring about efficiency.

**Flow:**
1. User creates challenge, selects which agents to run (checkboxes)
2. Each agent gets its own isolated working directory (with symlinks to the
   shared challenge files) and works independently
3. When any agent finds the flag, all other agents are automatically stopped
4. If the flag turns out to be wrong, the user can un-solve and restart or
   steer individual agents

**Isolation:** Each agent works in its own `_runs/<agent>/` subdirectory
within the challenge. This prevents file conflicts (e.g., two agents both
running `binwalk -e` to the same location).

### Mode 4: Parallel Agents (Managed)

Multiple agents work in parallel with a manager agent that coordinates them.
The manager periodically reviews all agents' progress, combines findings, and
gives each agent tailored instructions to avoid duplicated effort.

**When to use:** Hard challenges where you want multiple agents collaborating
rather than racing. The manager ensures agents explore different approaches
and share discoveries.

**Flow:**
1. User creates challenge, selects which agents to run
2. Each agent works in its own isolated directory, maintaining a
   `FINDINGS_<agent>.md` file (e.g., `FINDINGS_claude.md`)
3. Every N minutes, the manager reviews ALL agents' progress:
   - **WAIT** — agents are making good collective progress, no intervention
   - **SUMMARIZE** — the manager reads all `FINDINGS_<agent>.md` files,
     performs cross-agent blind spot analysis, and:
     - Writes `SUMMARY_FINDINGS.md` to each agent's directory (shared context)
     - Sends each agent a **tailored steer** based on what the others found
       and what this agent hasn't tried yet
   - **SHELVE** — all agents are stuck and further effort is unlikely to help.
     All agents are stopped and the challenge is shelved
4. The manager only intervenes if there has been meaningful progress since the
   last summary. If agents are still working through the previous instructions,
   it waits
5. When any agent finds the flag, all agents are auto-stopped

**Cross-agent coordination example:**
- Claude tried strings and binwalk but not steghide
- Codex tried steghide with an empty password but not with a dictionary
- Neither has tried zsteg

The manager would steer Claude: "Try steghide with common passwords from
rockyou.txt." It would steer Codex: "Try zsteg on all PNG files with all
channel combinations." Each agent gets instructions that fill gaps the others
missed.

## Manager Agent

The manager is a lightweight LLM (default: sonnet) that runs on a timer. It
does not solve challenges itself — it reviews solver agents' progress and
makes decisions.

### What the manager evaluates

1. **Progress assessment** — is the agent making forward progress or looping?
2. **Blind spot identification** — what techniques or tools haven't been tried?
3. **Approach evaluation** — is the current approach fundamentally wrong?
4. **Cross-agent deduplication** (mode 4) — are agents doing redundant work?

### Manager verdicts

| Verdict | Modes | Effect |
|---------|-------|--------|
| WAIT | 2, 4 | No intervention, agent is doing fine |
| STEER | 2 | Stop agent, restart with specific instructions |
| HANDOFF | 2 | Stop agent, start a different agent with context |
| SUMMARIZE | 4 | Combine findings, send tailored steers to each agent |
| SHELVE | 2, 4 | Stop all agents, mark challenge as shelved with notes |

### Manager timing

- **Review interval** — how often the manager checks (default: 10 minutes)
- **Minimum solve time** — don't review until the agent has had time to work
  (default: 5 minutes)
- **Cooldown** — after a steer or handoff, wait at least one interval before
  the next review

### Shelving

The manager shelves a challenge when it determines further attempts are
unlikely to succeed. This is a judgment call based on context, not a hard
limit on steers or handoffs. A challenge that's making partial progress with
each steer should keep going; one that's cycling through the same failed
approaches should be shelved.

Shelved challenges preserve their full output history and findings. They can
be un-shelved by the user at any time, which restarts solving with the
manager's notes as context.

## FINDINGS.md

The findings file is the primary knowledge transfer mechanism. It lives in
the challenge directory (or per-agent run directory in parallel modes) and
documents:

- What files were analyzed and what was found
- Which tools and techniques were tried
- Partial results, interesting artifacts, dead ends
- Hypotheses about the challenge

The file persists across retries, handoffs, and agent switches. Every new
agent reads it first to avoid repeating work.

| Mode | Findings file | Written by | Read by |
|------|--------------|------------|---------|
| Single | N/A | — | — |
| Single (Managed) | `FINDINGS.md` | Solver agent | Next agent on handoff |
| Parallel | N/A | — | — |
| Parallel (Managed) | `FINDINGS_<agent>.md` | Each solver agent | Manager |
| Parallel (Managed) | `SUMMARY_FINDINGS.md` | Manager | All solver agents |

## Retry with Context

When a challenge is retried (any mode), the previous attempt's output is
summarized and passed into the new prompt. The output log is cleared for a
fresh display, but the context carries forward. Combined with FINDINGS.md
(which persists on disk), this ensures agents never start completely blind
on a retry.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `manager_interval` | 10 | Minutes between manager reviews |
| `manager_model` | sonnet | Model used for manager LLM calls |
| `manager_min_solve_time` | 5 | Minutes before first review |
| `manager_agent_pool` | all agents | Agents available for handoff and parallel runs |
