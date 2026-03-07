# Stopping Events — Deep Dive

Detailed coverage of breakpoints, watchpoints, syscalls, and signals.

## Table of Contents

1. [Sync vs Async Flow](#sync-vs-async-flow)
2. [Breakpoints](#breakpoints)
3. [Watchpoints](#watchpoints)
4. [Syscall Handling](#syscall-handling)
5. [Signal Handling](#signal-handling)
6. [Common Attributes](#common-attributes)
7. [Recursion](#recursion)

---

## Sync vs Async Flow

Every stopping event can be either **synchronous** or **asynchronous**, determined by whether you pass a callback:

- **No callback (synchronous)**: Process stops and waits for your next command. You inspect state, then `d.cont()`.
- **With callback (asynchronous)**: libdebug temporarily stops the process, runs your callback, then auto-continues. The process only stays stopped if there's also a synchronous event pending.

Async mode is ideal for high-frequency events — counting breakpoint hits in a loop, logging syscalls, or doing side-channel analysis where you don't want to manually cont/wait for every hit.

There can be at most **one** callback or hijack per event instance (same address, same syscall, same signal). Setting a new one replaces the old one.

---

## Breakpoints

### Software vs Hardware

**Software breakpoints** (default): Implemented by patching a `0xCC` (INT3) byte into the code. Unlimited count, but conflict with self-modifying code or code integrity checks.

**Hardware breakpoints** (`hardware=True`): Use CPU debug registers. Limited to 4 on x86_64. No code patching, so they work with self-modifying code. Watchpoints also consume hardware breakpoint slots.

### Setting Breakpoints

```python
# Software at symbol
bp = d.breakpoint("main", file="binary")

# Software at offset from binary base
bp = d.breakpoint(0x1234, file="binary")

# Hardware at symbol
bp = d.breakpoint("func", hardware=True, file="binary")

# In a shared library
bp = d.breakpoint("printf", file="libc")

# At absolute address
bp = d.breakpoint(0x7ffff7a00000, file="absolute")

# With symbol + offset syntax
bp = d.breakpoint("play()+26", file="binary", hardware=True)
```

### Synchronous Usage

```python
bp1 = d.breakpoint("func_a", file="binary")
bp2 = d.breakpoint("func_b", file="binary")
d.cont()

# Check which one fired
if bp1.hit_on(d):
    print(f"Stopped at func_a, rax={d.regs.rax:#x}")
elif bp2.hit_on(d):
    print(f"Stopped at func_b, rdi={d.regs.rdi:#x}")
```

For multithreaded programs, pass a ThreadContext:
```python
for thread in d.threads:
    if bp.hit_on(thread):
        print(f"Thread {thread.tid} hit bp")
```

### Asynchronous Usage (Callbacks)

Callback signature: `callback(t: ThreadContext, bp: Breakpoint)`

```python
def on_hit(t, bp):
    print(f"Hit #{bp.hit_count}: rip={t.regs.rip:#x} rax={t.regs.rax:#x}")
    if bp.hit_count >= 1000:
        bp.disable()

d.breakpoint(0x1234, callback=on_hit, file="binary")
d.cont()
d.wait()  # blocks until sync event or process exit
```

You can also pass `callback=True` for an empty callback (just auto-continue, useful for counting hits without logging):

```python
bp = d.breakpoint(0x1234, callback=True, file="binary")
d.cont()
d.wait()
print(f"Total hits: {bp.hit_count}")
```

### Breakpoint Object

| Property/Method | Description |
|----------------|-------------|
| `address` | Breakpoint address |
| `hit_count` | Times triggered |
| `enabled` | Current state |
| `callback` | Associated callback (or None) |
| `enable()` | Enable |
| `disable()` | Disable |
| `hit_on(d_or_thread)` | Did this bp cause the stop? |

---

## Watchpoints

Hardware watchpoints trigger on memory read/write. They use hardware breakpoint slots (max 4 on x86_64).

```python
# Write watchpoint (default)
wp = d.watchpoint(0x404000, condition="w", length=8, file="binary")

# Read/write watchpoint
wp = d.watchpoint(0x404000, condition="rw", length=4, file="binary")

# Execute watchpoint (AMD64 only — same as hardware breakpoint)
wp = d.watchpoint(0x401000, condition="x", file="binary")

# With callback
def on_write(t, wp):
    print(f"Memory at {wp.address:#x} written by thread {t.tid}")

wp = d.watchpoint(0x404000, condition="w", length=8, callback=on_write, file="binary")
```

### Conditions

| Condition | Meaning | Architecture |
|-----------|---------|-------------|
| `"w"` | Write only | All |
| `"rw"` | Read or write | All |
| `"r"` | Read only | AArch64 only |
| `"x"` | Execute | AMD64 only |

### Alignment

On x86, the watched address must be aligned to `length`. E.g., a 4-byte watchpoint must be at a 4-byte-aligned address. Valid lengths: 1, 2, 4, 8.

---

## Syscall Handling

### Synchronous Handling

```python
handler = d.handle_syscall("write")
d.cont()

# Process stops at syscall entry OR exit
if handler.hit_on_enter(d):
    fd = d.syscall_arg0
    buf_addr = d.syscall_arg1
    count = d.syscall_arg2
    data = d.memory[buf_addr, count, "absolute"]
    print(f"write(fd={fd}, buf={data!r}, count={count})")
elif handler.hit_on_exit(d):
    ret = d.syscall_return
    print(f"write() returned {ret}")
```

### Asynchronous Handling

Callback signature: `callback(t: ThreadContext, handler: SyscallHandler)`

```python
def on_enter_write(t, handler):
    buf = t.memory[t.syscall_arg1, t.syscall_arg2, "absolute"]
    print(f"write({t.syscall_arg0}, {buf!r}, {t.syscall_arg2})")

def on_exit_write(t, handler):
    print(f"write returned {t.syscall_return}")

d.handle_syscall("write", on_enter=on_enter_write, on_exit=on_exit_write)
d.cont()
d.wait()
```

### Catch All Syscalls

Use `"*"` or `"all"`:

```python
d.handle_syscall("*", on_enter=log_all_syscalls)
```

### Syscall Hijacking

Replace one syscall with another. The replacement happens transparently to the process.

```python
# Simple replacement
d.hijack_syscall("read", "write")

# With custom arguments
d.hijack_syscall("read", "write",
    syscall_arg0=1,           # fd=stdout
    syscall_arg1=leak_addr,   # buffer to leak
    syscall_arg2=0x100        # length
)
```

### Syscall Identification

Syscalls can be specified by name (string) or number (int). Names are resolved via the system's syscall table.

### Pretty-Print Trace

```python
d.pprint_syscalls = True
d.cont()
```

### SyscallHandler Object

| Property/Method | Description |
|----------------|-------------|
| `syscall_number` | Syscall number |
| `hit_count` | Number of exits |
| `enabled` | Current state |
| `enable()` / `disable()` | Toggle |
| `hit_on(d)` | Entry or exit caused stop? |
| `hit_on_enter(d)` | Entry caused stop? |
| `hit_on_exit(d)` | Exit caused stop? |

---

## Signal Handling

### Catching Signals

```python
# Synchronous
catcher = d.catch_signal("SIGUSR1")
d.cont()
if catcher.hit_on(d):
    print(f"Caught signal {d.signal_number}")

# Asynchronous
def on_alarm(t, catcher):
    print(f"SIGALRM on thread {t.tid}")
    t.signal = 0  # suppress — don't deliver to process

d.catch_signal("SIGALRM", callback=on_alarm)
```

### Catch All Signals

```python
d.catch_signal("*", callback=on_any_signal)
```

Restricted: SIGKILL and SIGSTOP cannot be caught (kernel enforced).

### Signal Hijacking

```python
d.hijack_signal("SIGALRM", "SIGUSR1")
```

### Blocking Signals

```python
d.signals_to_block = ["SIGALRM", "SIGINT"]
```

Blocked signals are silently consumed — not delivered to the process.

### Sending Signals

```python
d.signal = 10    # SIGUSR1 — delivered on next continue
d.cont()

# Per-thread
d.threads[1].signal = 10
```

### SignalCatcher Object

| Property/Method | Description |
|----------------|-------------|
| `signal_number` | Signal being caught |
| `hit_count` | Times caught |
| `enabled` | Current state |
| `enable()` / `disable()` | Toggle |
| `hit_on(d)` | Did this signal cause the stop? |

---

## Common Attributes

All stopping events share these:

| Feature | Description |
|---------|-------------|
| `enabled` / `enable()` / `disable()` | Toggle the event on/off |
| `callback` | Set/change/remove (`None`) the callback |
| `hit_count` | Number of times triggered |
| `hit_on(d_or_thread)` | Check if this event caused the current stop |

Setting `callback=True` registers an empty callback (auto-continue without logging).

---

## Recursion

When a callback or hijack itself triggers another event, the `recursive` parameter controls whether that nested event fires:

```python
# Non-recursive (default) — nested triggers are ignored
d.handle_syscall("write", on_enter=my_callback, recursive=False)

# Recursive — nested triggers also fire
d.handle_syscall("write", on_enter=my_callback, recursive=True)
```

libdebug detects infinite recursion loops and raises `RuntimeError`:
```python
# This raises RuntimeError — infinite loop
d.hijack_syscall("read", "write", recursive=True)
d.hijack_syscall("write", "read", recursive=True)
```
