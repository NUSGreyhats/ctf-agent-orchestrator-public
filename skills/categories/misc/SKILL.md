---
name: misc
description: Use when the challenge category is unclear or mixed (puzzles, custom encodings, protocol oddities, trick questions, OSINT-like hints, or layered artifacts that don't fit cleanly into web/pwn/rev/crypto/forensics).
---

# CTF Misc

Use this when challenge type is ambiguous, intentionally deceptive, or multi-layered.

## 1. Clarify Objective

- Confirm answer format (`flag{...}` or plain value).
- Extract every explicit hint from challenge text.
- Identify any known nouns: file names, usernames, timestamps, places, URLs, handles.

## 2. First-Pass Enumeration

```bash
find . -maxdepth 4 -type f | sort
ctfgrep -i . "flag{"
rg -uuu -n "flag|ctf|hint|secret|pass|token|key|http|https|discord|telegram" .
```

## 3. Encoding/Transformation Checks

Try fast transforms before deep reversing:
- base64/base32/base85
- hex and mixed hex-ascii
- rot13/caesar/substitution hints
- xor with short keys
- compressed layers (`gzip`, `xz`, `zstd`)

## 4. Artifact Oddities

- Wrong extension / magic bytes mismatch
- Hidden chunks/metadata
- Embedded archives or nested payloads
- Unicode confusables or zero-width characters

## 5. OSINT-Style Leads (If Applicable)

When prompt references people/orgs/places/events:
- Parse likely usernames and handles
- Check challenge-provided URLs/domains first
- Correlate timestamps and identifiers across artifacts

## 6. Layered Challenge Strategy

If one step yields another artifact, recurse:
1. Save extracted artifact under `output/`
2. Re-run triage (`file`, `strings`, `ctfgrep`, `exiftool`)
3. Continue until direct flag candidate appears

## 7. Stop Conditions

If no direct path emerges:
- Return top 3 hypotheses with supporting evidence.
- List concrete next experiments, not generic guesses.
- Preserve reproducible command history in notes/output.
