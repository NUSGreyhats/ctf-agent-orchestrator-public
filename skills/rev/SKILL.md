---
name: rev
description: Use when the challenge involves reverse engineering binaries, bytecode, custom VMs, obfuscated logic, anti-debugging, or hidden checks in executables. Prefer this for static/dynamic program analysis when there is no primary web/service exploit path.
---

# CTF Reverse Engineering

Use this workflow for ELF/PE/Mach-O binaries, scripts compiled to bytecode, and custom challenge formats where the flag is computed by program logic.

## 1. Fast Triage

```bash
file ./challenge
checksec --file=./challenge || true
strings -a ./challenge | rg -i "flag|ctf|pico|htb|key|secret"
```

If challenge files include metadata/manifests, read those first for hints.

## 2. Static Analysis First

Use headless IDA and find:
- Input validation path
- String compare path
- Decoding/decryption routines
- Dead code or decoy checks

Useful checks:
```bash
ctfgrep -i . "flag{"
rg -uuu -n "flag|check|verify|password|secret" .
```

## 3. Dynamic Analysis

When static analysis is insufficient, move to debugger-driven validation:
- Break at compare branches
- Inspect transformed buffers before final checks
- Capture derived keys and decoded plaintext

For userland binaries, prefer `libdebug-debugging`.
For kernel targets, switch to `kernel-gef-debugging`.

## 4. Common Patterns

- XOR/add/sub rolling transforms
- Table lookup substitutions
- Position-dependent arithmetic
- Stateful checks split across functions
- VM dispatch loops (`switch(opcode)` patterns)
- Anti-debug checks (`ptrace`, timing, proc status)

## 5. Practical Strategies

### Patch-and-run
Patch conditional jumps or return values to dump post-check state.

### Re-implement checker
Translate critical transform into Python and solve offline.

### Hook and trace
Instrument suspicious routines and log intermediate buffers.

## 6. Non-native Formats

### Python bytecode
```python
import marshal, dis
with open("chall.pyc", "rb") as f:
    f.read(16)
    code = marshal.load(f)
dis.dis(code)
```

### WASM
```bash
wasm2wat chall.wasm -o chall.wat
```

### APK
Use `apk-analysis` skill; this skill remains a fallback for logic-focused review.

## 7. Output Discipline

- Keep notes on function addresses and findings.
- Save scripts/patches under `output/`.
- Verify final candidate flag format exactly before returning.
