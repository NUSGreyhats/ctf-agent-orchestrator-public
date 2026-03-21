---
name: pwn
description: Use when the challenge involves binary exploitation — buffer overflow, ROP chains, format string, heap exploitation (tcache, House of Orange/Apple), shellcode, seccomp bypass, or kernel pwn. Also use when a binary is provided alongside a remote service (host:port).
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation challenges. Start with `checksec` to understand protections, then choose an exploit strategy from the decision tree below.

## Initial Analysis

```bash
file binary
checksec --file=binary
strings binary | grep -i flag
```

## Protection Implications

| Protection | Status | Implication |
|-----------|--------|-------------|
| PIE | Disabled | All addresses are fixed — direct overwrites work |
| RELRO | Partial | GOT is writable — GOT overwrite attacks possible |
| RELRO | Full | GOT read-only — target hooks, vtables, return addresses |
| NX | Enabled | No shellcode on stack/heap — use ROP |
| Canary | Present | Need leak or avoid stack overflow (use heap) |

**Quick decision tree:**
- Partial RELRO + No PIE → GOT overwrite (easiest)
- Full RELRO → target `__free_hook`, `__malloc_hook` (glibc < 2.34), or return addresses
- Stack canary → prefer heap attacks or leak canary first

## Stack Buffer Overflow

1. Find offset: `cyclic 200` then `cyclic -l <value>`
2. No PIE + No canary = direct ROP
3. Canary leak via format string or brute-force byte-by-byte on forking servers (7*256 attempts max)

Stack alignment: modern glibc needs 16-byte alignment; SIGSEGV in `movaps` = add extra `ret` gadget.

## ROP Chains

Leak libc via `puts@PLT(puts@GOT)`, return to vuln, stage 2 with `system("/bin/sh")`.

```bash
ROPgadget --binary binary | grep "pop rdi"
one_gadget libc.so.6
```

- **ret2csu:** `__libc_csu_init` gadgets control `rdx`, `rsi`, `edi` — universal 3-arg call
- **Raw syscall:** When `system()`/`execve()` crash (CET/IBT), use `pop rax; ret` + `syscall; ret`
- **Stack pivot:** `xchg rax, esp` when overflow too small for full chain
- **ret2vdso:** No gadgets in binary? vDSO mapped into every process has them

## Format String

- Leak stack: `%p.%p.%p.%p.%p.%p`
- Leak specific: `%7$p`
- Write: `%n` (4-byte), `%hn` (2-byte), `%hhn` (1-byte)
- GOT overwrite for code execution (Partial RELRO required)

## Shellcode

```python
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
```

Input reversal: pre-reverse shellcode, use partial RIP overwrite, trampoline `jmp short` to NOP sled.

## Seccomp Bypass

Alternative syscalls when seccomp blocks `open()`/`read()`:
- `openat()` (257), `openat2()` (437, often missed!)
- `sendfile()` (40), `readv()`/`writev()`
- `mmap()` (9) — map flag file into memory
- `pread64()` (17)

```bash
seccomp-tools dump ./binary
```

RETF architecture switch: `retf` to CS=0x23 (32-bit mode) — `int 0x80` uses different syscall numbers not covered by 64-bit filters.

## Heap Exploitation

- **tcache poisoning** (glibc 2.26+): corrupt freed chunk fd pointer
- **Safe-linking** (glibc 2.32+): fd mangled as `ptr ^ (chunk_addr >> 12)`
- **UAF:** free doesn't NULL pointer → reallocate same-size object to overwrite function pointer
- **House of Orange:** corrupt top chunk size → sysmalloc frees old top → FSOP chain
- **House of Apple 2** (glibc 2.34+): FSOP via `_IO_wfile_jumps` when hooks removed
- **ret2dlresolve:** forge `Elf64_Sym`/`Rela` to resolve arbitrary libc function without leak

Check glibc version: `strings libc.so.6 | grep GLIBC`

Freed chunks contain libc pointers (fd/bk) → leak via error messages or missing null-termination.

## Kernel Exploitation

- **modprobe_path overwrite:** overwrite with evil script, `execve` non-ELF → kernel runs script as root
- **tty_struct kROP:** `open("/dev/ptmx")` allocates in kmalloc-1024, overwrite ops vtable
- **userfaultfd:** register region, kernel page fault blocks thread → deterministic race window
- **KASLR bypass:** `__ksymtab` relative offsets in multi-stage exploit
- **KPTI bypass:** `swapgs_restore_regs_and_return_to_usermode + 22` trampoline

Heap spray structures: `tty_struct` (kmalloc-1024), `poll_list` (variable), `user_key_payload` (variable), `seq_operations` (kmalloc-32).

## Python Sandbox Escape

- AST bypass via f-strings
- Audit hook bypass with `b'flag.txt'` (bytes vs str)
- MRO-based `__builtins__` recovery

## Pwntools Template

```python
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = ELF('./libc.so.6')

# context.log_level = 'debug'
# r = process(binary)
r = remote('host', port)

# Exploit here

r.interactive()
```

## Common Pitfalls

- rdx clobbered to 1 after `puts()` — need `pop rdx; pop rbx; ret` from libc
- After `execve`, `sleep(1)` then `sendline(b'cat /flag*')`
- Source code with `pthread`/`usleep` → look for race conditions
