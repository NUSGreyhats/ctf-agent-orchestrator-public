---
name: ground-your-findings
description: >
  Use when solving CTF challenges, debugging exploits, reviewing
  vulnerabilities, or making technical claims that should be verified with
  evidence. This skill forces hypotheses to be grounded through local
  reproduction, instrumentation, emulation, controlled probes, or other direct
  observations before relying on conclusions.
---

# Ground Your Findings

Do not treat static reasoning, pattern matching, or intuition as proof. Use
them to form hypotheses, then seek ground truth through the cheapest reliable
verification.

## Core Rules

- Treat every important conclusion as a hypothesis until verified.
- Prefer local testing before remote interaction when challenge files, source,
  binaries, Docker setup, or enough protocol details are available.
- Use the remote service as final confirmation, or when local reproduction is
  unavailable, incomplete, or deployment-specific behavior matters.
- Prefer executable evidence over static analysis: run code, instrument it,
  emulate it, trace it, fuzz it, or build a minimal harness.
- Before declaring a vulnerability, exploit path, root cause, or flag
  candidate, verify the behavior directly where practical.
- Keep probes minimal and controlled. Do not brute force or spam remote
  services when local testing can answer the question.
- If verification is not possible, label the claim as unverified and explain
  the blocker.

## Evidence Priority

Prefer evidence in this order:

1. Local reproduction with challenge-provided files, source, containers, or
   binaries.
2. Debugger, trace, emulator, symbolic execution, harness, or targeted script.
3. Controlled remote probe against the challenge service.
4. Static source, disassembly, decompiler, config, or protocol analysis.
5. Prior experience, pattern recognition, or intuition.

Higher-priority evidence should override lower-priority assumptions.

## CTF Workflow

When challenge files are present:

- Inspect the files enough to understand likely execution paths.
- Run the program, service, container, or relevant component locally.
- Create the smallest test that confirms or rejects the hypothesis.
- Use logs, debugger output, traces, request/response bodies, or script output
  as evidence.
- Only connect to remote after local behavior is understood, unless the
  challenge is inherently remote-only.
- Confirm remote differences explicitly instead of assuming local and remote
  match.

When only a remote target is available:

- Start with harmless discovery and minimal probes.
- Record exact inputs and observed outputs.
- Change one variable at a time.
- Avoid relying on inferred behavior when a direct request can verify it.

## Claim Discipline

For each meaningful finding, keep the distinction clear:

- Hypothesis: what might be true.
- Test: what was run or observed.
- Evidence: concrete output, behavior, trace, or response.
- Conclusion: what the evidence supports.

Do not write conclusions like "this should work" when the real status is "this
looks plausible but is untested."

## Before Acting

Before submitting a flag, launching an exploit, or marking a task solved, ask:

- Did I observe the behavior directly?
- Did I test locally when local testing was available?
- Did I confirm remote behavior if the final target is remote?
- Is there an untested assumption that could invalidate the conclusion?

If the answer exposes a gap, run the smallest useful verification first.
