# libdebug API Reference

Detailed API for all core classes. For quick-start patterns, see SKILL.md.

## Table of Contents

1. [Debugger Object](#debugger-object)
2. [ThreadContext](#threadcontext)
3. [PipeManager (I/O)](#pipemanager)
4. [Memory Access](#memory-access)
5. [Register Access](#register-access)
6. [Symbol Resolution](#symbol-resolution)
7. [Memory Maps](#memory-maps)
8. [Logging & Context](#logging--context)

---

## Debugger Object

The main interface. Created with `debugger(argv, ...)`.

### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `argv` | `str` or `list[str]` | required | Binary path and arguments |
| `aslr` | `bool` | `True` | Enable/disable ASLR |
| `env` | `dict` | `None` | Environment variables |
| `escape_antidebug` | `bool` | `False` | Bypass ptrace-based anti-debug |
| `continue_to_binary_entrypoint` | `bool` | `True` | Skip dynamic loader, stop at `_start` |
| `auto_interrupt_on_command` | `bool` | `False` | ASAP mode — auto-interrupt for state reads |
| `fast_memory` | `bool` | `True` | Use `/proc/pid/mem` for memory access |
| `kill_on_exit` | `bool` | `True` | Kill process when debugger is garbage-collected |
| `follow_children` | `bool` | `True` | Automatically track forked child processes |

### Process Control Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `run(redirect_pipes=True, timeout=None)` | `PipeManager` | Spawn process |
| `attach(pid)` | `None` | Attach to running process |
| `cont()` | `None` | Continue execution |
| `wait()` | `None` | Block until stopping event |
| `step()` / `si()` | `None` | Single instruction step |
| `next()` | `None` | Step over call instructions |
| `step_until(pos, max_steps=-1, file="hybrid")` / `su()` | `None` | Step until address |
| `finish(heuristic="backtrace")` / `fin()` | `None` | Step out of function |
| `interrupt()` | `None` | Force-stop process |
| `kill()` | `None` | Send SIGKILL |
| `detach()` | `None` | Detach from process |
| `terminate()` | `None` | Kill + deallocate debugger |

### Stopping Event Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `breakpoint(addr, hardware=False, condition='x', length=1, callback=None, file='hybrid')` | `Breakpoint` | Set breakpoint |
| `bp(...)` | `Breakpoint` | Alias for `breakpoint()` |
| `watchpoint(pos, condition='w', length=1, callback=None, file='hybrid')` | `Breakpoint` | Set watchpoint |
| `catch_signal(signal, callback=None, recursive=False)` | `SignalCatcher` | Catch signal |
| `hijack_signal(original, new, recursive=False)` | `SignalCatcher` | Replace signal |
| `handle_syscall(syscall, on_enter=None, on_exit=None, recursive=False)` | `SyscallHandler` | Handle syscall |
| `hijack_syscall(original, new, recursive=False, **kwargs)` | `SyscallHandler` | Replace syscall |

### State Properties

| Property | Type | Description |
|----------|------|-------------|
| `regs` | `Registers` | Register access for main thread |
| `memory` / `mem` | `MemoryView` | Memory access |
| `threads` | `list[ThreadContext]` | All threads |
| `children` | `list[Debugger]` | Child process debuggers |
| `breakpoints` | `dict[int, Breakpoint]` | Active breakpoints (addr → bp) |
| `maps` | `MemoryMapList` | Memory maps |
| `symbols` | `SymbolList` | Symbol table |
| `dead` | `bool` | Process exited |
| `running` | `bool` | Process not stopped |
| `zombie` | `bool` | Main thread is zombie |
| `exit_code` | `int or None` | Exit code |
| `exit_signal` | `str or None` | Exit signal |
| `arch` | `str` | CPU architecture |

### Syscall Properties (architecture-agnostic)

| Property | Description |
|----------|-------------|
| `syscall_number` | Current syscall number |
| `syscall_arg0` through `syscall_arg5` | Syscall arguments |
| `syscall_return` | Syscall return value |
| `signal` | Signal to forward on continue |
| `signal_number` | Signal number |
| `signals_to_block` | List of signals to filter |

### Mutable Properties

These can be changed between `d.kill()` and `d.run()`:
- `argv` — change binary args for brute-force loops
- `env` — change environment
- `path` — change binary path
- `pprint_syscalls` — enable/disable syscall tracing

### Pretty Printing

| Method | Description |
|--------|-------------|
| `pprint_regs()` / `pprint_registers()` | Common registers |
| `pprint_regs_all()` / `pprint_registers_all()` | All registers |
| `pprint_maps()` | Memory maps |
| `pprint_backtrace()` | Stack trace |
| `pprint_memory(start, end, file, override_word_size, integer_mode)` | Hex dump |

### Snapshot Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `create_snapshot(level="base", name=None)` | `ProcessSnapshot` | Capture state |
| `load_snapshot(path)` | `Snapshot` | Load from JSON file |

### GDB Migration

| Method | Description |
|--------|-------------|
| `gdb(migrate_breakpoints=True, open_in_new_process=True, blocking=True)` | Open GDB |
| `wait_for_gdb()` | Wait for non-blocking GDB to finish |

---

## ThreadContext

Represents a single thread. Same state-access API as Debugger but thread-specific.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `regs` | `Registers` | Thread's registers |
| `memory` / `mem` | `MemoryView` | Process memory (shared) |
| `debugger` | `Debugger` | Parent debugger |
| `instruction_pointer` / `rip` | `int` | Current IP |
| `process_id` / `pid` | `int` | Process ID |
| `thread_id` / `tid` | `int` | Thread ID |
| `saved_ip` | `int` | Return address of current function |
| `dead` / `running` / `zombie` | `bool` | Thread state |
| `exit_code` / `exit_signal` | `int/str` | Exit info |
| `syscall_*` | `int` | Syscall parameters |
| `signal` / `signal_number` | `str/int` | Signal handling |

### Methods

| Method | Description |
|--------|-------------|
| `step()` / `si()` | Single step this thread |
| `step_until(pos, max_steps, file)` / `su()` | Step until address |
| `finish(heuristic)` / `fin()` | Step out of function |
| `next()` | Step over calls |
| `backtrace(as_symbols=False)` | Get stack trace |
| `pprint_backtrace()` | Pretty print backtrace |
| `pprint_regs()` / `pprint_regs_all()` | Pretty print registers |
| `create_snapshot(level, name)` | Create ThreadSnapshot |
| `set_as_dead()` | Mark thread as dead |

The Debugger object acts as a facade for `d.threads[0]` (main thread). So `d.regs.rax` is the same as `d.threads[0].regs.rax`.

---

## PipeManager

Returned by `d.run()`. Handles process stdin/stdout/stderr.

### Receive Methods

| Method | Description |
|--------|-------------|
| `recv(numb=4096, timeout=default)` | Read from stdout |
| `recverr(numb=4096, timeout=default)` | Read from stderr |
| `recvuntil(delims, occurrences=1, drop=False, timeout=default, optional=False)` | Read until delimiter |
| `recverruntil(delims, occurrences=1, drop=False, timeout=default, optional=False)` | Read stderr until delimiter |
| `recvline(numlines=1, drop=True, timeout=default, optional=False)` | Read line(s) from stdout |
| `recverrline(numlines=1, drop=True, timeout=default, optional=False)` | Read line(s) from stderr |

### Send Methods

| Method | Description |
|--------|-------------|
| `send(data)` | Write to stdin |
| `sendline(data)` | Write + newline |
| `sendafter(delims, data, occurrences=1, drop=False, timeout=default, optional=False)` | Send after receiving delimiter |
| `sendlineafter(delims, data, occurrences=1, drop=False, timeout=default, optional=False)` | Sendline after delimiter |

### Other

| Method/Property | Description |
|----------------|-------------|
| `interactive(prompt="$ ", auto_quit=False)` | Interactive mode |
| `close()` | Close pipes |
| `timeout_default` | Default timeout in seconds (writable) |

---

## Memory Access

Via `d.memory` or `thread.memory`. Supports multiple addressing modes.

### Addressing Modes

| Syntax | Mode | Example |
|--------|------|---------|
| `d.memory[addr]` | Single byte | `d.memory[0x1000]` |
| `d.memory[start:end]` | Slice | `d.memory[0x1000:0x1010]` |
| `d.memory[addr, size]` | Base + length (hybrid) | `d.memory[0x1000, 0x10]` |
| `d.memory["sym", size]` | Symbol + length | `d.memory["main", 8]` |
| `d.memory["sym+XX"]` | Symbol + hex offset | `d.memory["main+a8"]` |
| `d.memory["sym1":"sym2"]` | Symbol range | `d.memory["main":"main+0f"]` |
| `d.memory[addr, size, "binary"]` | Relative to binary base | `d.memory[0x1000, 0x10, "binary"]` |
| `d.memory[addr, size, "libc"]` | Relative to libc base | `d.memory[0x1000, 0x10, "libc"]` |
| `d.memory[addr, size, "absolute"]` | Absolute virtual address | `d.memory[0x7fff, 0x10, "absolute"]` |
| `d.memory[addr, size, "hybrid"]` | Try absolute, fallback binary | Default mode |

### File Parameter

The `file` parameter in addressing determines how addresses are resolved:
- `"hybrid"` (default) — tries absolute first, falls back to relative
- `"binary"` — offset from the binary's base address
- `"libc"` — offset from libc's base address
- `"absolute"` — fixed virtual address
- Any other string — matches backing file name

### Search Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `find(value, file=None, start=None, end=None)` | `list[int]` | Find bytes/int in memory |
| `find_pointers(where, target, step=None)` | `list[tuple[int,int]]` | Find pointer chains between regions |
| `telescope(addr, max_depth=5, min_str_len=3, max_str_len=50)` | `list[int\|str]` | Follow pointer chain |

### Writing

```python
d.memory[addr, size] = b"data"
d.memory[addr, size, "binary"] = b"data"
d.memory["symbol"] = b"value"
```

---

## Register Access

Via `d.regs` or `thread.regs`.

### AMD64 (x86_64)

- **General**: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8–R15
- **Sub-registers**: EAX/AX/AH/AL, etc. for all GP registers
- **Special**: RIP, EFLAGS
- **Segment**: CS, DS, ES, FS, GS, SS, FS_BASE, GS_BASE
- **Vector**: XMM0–15, YMM0–15, ZMM0–15
- **Floating point**: ST(0)–ST(7), MM0–MM7

### AArch64

- **General**: X0–X30 (W0–W30 for 32-bit), XZR, SP, PC
- **Flags**: PSTATE
- **Vector**: V0–V31, Q0–Q31, D0–D31, S0–S31, H0–H31, B0–B31

### i386

- **General**: EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP, EIP, EFLAGS
- **Segment**: CS, DS, ES, FS, GS, SS
- **Vector**: XMM0–7, YMM0–7
- **Floating point**: ST(0)–ST(7)

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `d.regs.filter(value)` | `list[str]` | Find registers containing value |

---

## Symbol Resolution

Control symbol lookup depth via `libcontext`:

```python
from libdebug import libcontext

libcontext.sym_lvl = 5  # default

# Temporary override
with libcontext.tmp(sym_lvl=3):
    d.breakpoint("main")
```

| Level | Source |
|-------|--------|
| 0 | Disabled |
| 1 | .symtab + .dynsym |
| 2 | DWARF debug info |
| 3 | External debug files (.gnu_debuglink) |
| 4 | External debug DWARF |
| 5 | Download via debuginfod (default) |

### Symbol Object

| Property | Type | Description |
|----------|------|-------------|
| `start` | `int` | Start address |
| `end` | `int` | End address |
| `name` | `str` | Symbol name |
| `backing_file` | `str` | Defining file |
| `is_external` | `bool` | External symbol |

---

## Memory Maps

### MemoryMap Object

| Property | Type | Description |
|----------|------|-------------|
| `start` / `base` | `int` | Start address |
| `end` | `int` | End address |
| `permissions` | `str` | rwx flags |
| `size` | `int` | Map size |
| `offset` | `int` | File offset |
| `backing_file` | `str` | Mapped file |

### MemoryMapList Methods

```python
d.maps.filter("libc")         # by backing file name
d.maps.filter(0x7ffff7000000)  # by address
```

---

## Logging & Context

```python
from libdebug import libcontext

# Logger types
libcontext.general_logger = "DEBUG"   # DEBUG, INFO, WARNING, SILENT
libcontext.pipe_logger = "DEBUG"
libcontext.debugger_logger = "DEBUG"

# Temporary
with libcontext.tmp(general_logger="DEBUG"):
    d.cont()

# Terminal for GDB migration
libcontext.terminal = ['tmux', 'splitw', '-h']
```
