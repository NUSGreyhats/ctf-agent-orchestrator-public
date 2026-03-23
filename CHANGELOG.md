# Changelog

## Unreleased

### Four Solving Modes

The challenge model has been rebuilt around four solving modes, replacing the
flat single-agent-per-challenge approach.

**Single** — One agent, no manager. The original behavior, preserved as the
simplest option for quick challenges or when you want full manual control.

**Single (Managed)** — One agent with automated oversight. A manager agent
reviews progress at fixed intervals and can steer the solver with specific
instructions, hand off to a different agent from the configured pool, or
shelve the challenge if it's stuck. This exists because hard challenges
often benefit from trying multiple agents — the manager automates what was
previously a manual "stop, switch agent, retry" cycle.

**Parallel** — Multiple agents race on the same challenge simultaneously.
When any agent finds the flag, all others are automatically stopped. This
exists because different agents have different strengths; racing them avoids
having to guess which one will work best.

**Parallel (Managed)** — Multiple agents with cross-agent coordination. The
manager periodically reads all agents' findings, produces a combined summary,
and gives each agent tailored instructions to avoid duplicated effort. This
exists because parallel agents without coordination often explore the same
dead ends independently — the manager ensures they cover different ground.

### Challenge Runs

Each challenge now contains one or more "runs" instead of storing agent state
directly. Each run has its own agent, process, output stream, WebSocket
connections, and working directory. This is the architectural change that
enables all four modes — single modes have one run, parallel modes have many.

In parallel modes, each run gets an isolated directory with symlinks to the
shared challenge files, preventing file conflicts when multiple agents work
simultaneously (e.g., both running `binwalk -e` to the same location).

### Manager Agent

A background manager agent that reviews solving challenges and makes
decisions. Runs on a timer (default: every 10 minutes) using a lightweight
model (default: sonnet).

**Why this exists:** AI agents frequently get stuck in loops, miss obvious
techniques, or fixate on wrong approaches. Rather than requiring constant
human monitoring, the manager provides automated course correction.

Verdicts by mode:
- Single Managed: WAIT, STEER (specific instructions), HANDOFF (switch
  agent), SHELVE
- Parallel Managed: WAIT, SUMMARIZE (cross-agent coordination with tailored
  per-agent steers), SHELVE

The manager uses blind spot identification (what hasn't been tried?),
progress assessment (stuck or making progress?), and unconventional approach
suggestions to decide interventions.

### FINDINGS.md Knowledge Transfer

In managed modes, agents maintain a FINDINGS.md file documenting what they've
tried and discovered. This file persists across retries and handoffs, serving
as the primary knowledge transfer mechanism between agents.

**Why this exists:** Without persistent findings, each new agent (on handoff
or retry) starts blind and repeats the same failed approaches. FINDINGS.md
gives the next agent a running start.

In parallel managed mode, each agent writes its own FINDINGS file, and the
manager combines them into SUMMARY_FINDINGS.md for cross-agent awareness.

### Retry with Context

When a challenge is retried, the previous attempt's output is summarized and
passed into the new prompt. The output log is cleared for a fresh display,
but the context carries forward.

**Why this exists:** The old retry was a complete reset — the agent had zero
context about what was tried before. This led to agents repeating the exact
same failed approaches on retry.

### Shelved Status

Challenges can now be shelved (by the manager or manually) when further
attempts are unlikely to succeed. Shelved challenges preserve their full
output history and findings, and can be un-shelved at any time.

**Why this exists:** "Failed" was the only terminal state, but it doesn't
distinguish between "crashed" and "we tried everything reasonable." Shelving
captures the manager's assessment and preserves context for later.

### Un-solve

Solved challenges can be reverted to failed status if the flag turns out to
be wrong. All runs are stopped and the user can retry or steer.

**Why this exists:** In parallel mode, an agent might report a false flag
that triggers auto-stop of all other agents. The user needs a way to undo
this and get the agents working again.

### Skills Reorganization

Skills restructured from a flat directory into three groups:
- `methodology/` — Entrypoint skill, read first for every challenge
- `categories/` — CTF challenge categories (crypto, forensics/*, pwn, rev,
  web, misc)
- `tools/` — Tool-specific skills (IDA, libdebug, kernel-gef, APK analysis)

**Why this restructured:** The old flat layout mixed categories and tools at
the same level with inconsistent naming. The new structure makes the
hierarchy clear — methodology routes to categories, categories reference
tools.

### Skill Routing via Methodology

The solver prompt no longer injects all 14 skill descriptions into every
challenge. Instead, it points to the methodology skill, which contains a
routing table mapping categories and tools to their file paths.

**Why this changed:** Injecting the full skill catalog wasted ~30 lines of
prompt context on every challenge. Moving the routing into methodology means
the agent reads it once during triage and loads only what it needs.

### Bug Fix: WebSocket Set Iteration

Fixed a race condition in `broadcast()` where iterating over `ws_clients`
while `await`ing could fail with "set changed size during iteration" if a
WebSocket connected or disconnected during the loop.
