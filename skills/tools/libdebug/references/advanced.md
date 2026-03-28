# Advanced Features

Multithreading, multiprocessing, snapshots, anti-debugging, and GDB migration.

## Table of Contents

1. [Multithreading](#multithreading)
2. [Multiprocessing](#multiprocessing)
3. [Snapshots](#snapshots)
4. [Snapshot Diffs](#snapshot-diffs)
5. [Anti-Debugging Bypass](#anti-debugging-bypass)
6. [GDB Migration](#gdb-migration)

---

## Multithreading

libdebug enforces coherent thread state: when one thread stops, all threads stop. When you call `d.cont()`, all threads resume.

### Accessing Threads

```python
for thread in d.threads:
    print(f"Thread {thread.tid}: rip={thread.regs.rip:#x}")
    thread.pprint_regs()
```

`d.threads[0]` is always the main thread. The `Debugger` object is a facade for the main thread — `d.regs.rax` is equivalent to `d.threads[0].regs.rax`.

### Thread-Specific Stepping

```python
# Step only thread 2
d.threads[2].step()

# Step thread 2 until address
d.threads[2].step_until(0x1234, file="binary")

# Finish current function on thread 1
d.threads[1].finish()
```

### Breakpoints in Multithreaded Programs

Software breakpoints affect all threads (they patch shared code). To identify which thread triggered a breakpoint:

```python
# Synchronous — check manually
for thread in d.threads:
    if bp.hit_on(thread):
        print(f"Thread {thread.tid} hit breakpoint at {bp.address:#x}")

# Asynchronous — callback receives the thread
def on_bp(t, bp):
    print(f"Thread {t.tid} hit bp at {bp.address:#x}")

d.breakpoint(0x1000, callback=on_bp, file="binary")
```

### Shared State

- **Memory**: Shared across all threads (same address space)
- **Memory maps**: Shared (process-level)
- **Symbols**: Shared (process-level)
- **Registers**: Per-thread
- **Stack**: Per-thread

### Zombie Threads

When a thread exits, it enters zombie state until reaped. libdebug handles reaping automatically.

```python
if d.threads[1].zombie:
    print("Thread 1 has exited")
```

---

## Multiprocessing

Since version 0.8, libdebug tracks child processes created by `fork()`, `clone()`, etc.

### Automatic Tracking

By default (`follow_children=True`), each child gets its own Debugger object:

```python
d = debugger("./server")
d.run()
d.cont()
d.wait()

for child in d.children:
    print(f"Child PID: {child.pid}")
    # Each child is a full Debugger with its own breakpoints, state, etc.
    child.breakpoint("handle_request", file="binary")
    child.cont()
```

### Disabling Child Tracking

```python
d = debugger("./binary", follow_children=False)

# Or dynamically
d.follow_children = False
```

### What Children Inherit

Children inherit debugger properties (ASLR setting, fast_memory, etc.) at creation time, but they're independent after that. Children do NOT inherit:
- Breakpoints
- Watchpoints
- Syscall handlers
- Signal catchers

You must set these up on each child independently.

### Pipe I/O with Children

Child processes share the same pipe file descriptors as the parent (POSIX fork semantics). You interact with them through the same PipeManager from `d.run()`.

---

## Snapshots

Snapshots capture process state at a point in time. Useful for comparing before/after or saving state for offline analysis.

### Snapshot Levels

| Level | Captures | Use Case |
|-------|----------|----------|
| `"base"` | Registers + memory page metadata | Quick state check |
| `"writable"` | Base + writable page contents | Most debugging needs |
| `"full"` | Base + ALL page contents | Complete forensics |

### Creating Snapshots

```python
# Process-level (includes all threads)
snap = d.create_snapshot(level="writable", name="before_exploit")

# Thread-level
thread_snap = d.threads[0].create_snapshot(level="base")
```

### Saving and Loading

```python
# Save to JSON
snap.save("/tmp/snapshot.json")

# Load from JSON
loaded = d.load_snapshot("/tmp/snapshot.json")
```

### Inspecting Snapshots

Snapshots have the same read-only interface as live state:

```python
print(f"RIP at snapshot: {snap.regs.rip:#x}")
print(f"RAX: {snap.regs.rax:#x}")

# Memory (only if level is "writable" or "full")
data = snap.memory[0x1000, 0x10, "binary"]

# Maps
for m in snap.maps:
    print(f"{m.start:#x}-{m.end:#x} {m.permissions}")

# Backtrace
snap.pprint_backtrace()
snap.pprint_regs()
```

### Snapshot Properties

| Property | Description |
|----------|-------------|
| `name` | Snapshot name |
| `arch` | Architecture |
| `snapshot_id` | Unique ID |
| `level` | Capture level |
| `regs` / `registers` | Register access |
| `memory` / `mem` | Memory access |
| `maps` | Memory maps |

---

## Snapshot Diffs

Compare two snapshots to see what changed:

```python
snap1 = d.create_snapshot(level="writable", name="before")
d.cont()
d.wait()
snap2 = d.create_snapshot(level="writable", name="after")

diff = snap1.diff(snap2)
```

### Register Diffs

```python
for reg_diff in diff.regs:
    if reg_diff.has_changed:
        print(f"  {reg_diff.old_value:#x} -> {reg_diff.new_value:#x}")
```

### Memory Map Diffs

```python
for map_diff in diff.maps:
    # Access changed regions
    pass
```

The diff level is the minimum of the two snapshot levels. You can't diff memory contents if one snapshot is `"base"` level.

---

## Anti-Debugging Bypass

Many binaries detect debuggers via `ptrace(PTRACE_TRACEME, ...)`. If the process is already traced, ptrace returns -1 and the binary exits or changes behavior.

### Automatic Bypass

```python
d = debugger("./protected", escape_antidebug=True)
```

This makes libdebug intercept the ptrace syscall and fake a success return, so the binary thinks it's not being debugged.

### Manual Bypass via Syscall Hijacking

For more complex anti-debug (e.g., checking `/proc/self/status` for TracerPid):

```python
def fake_ptrace(t, handler):
    if t.syscall_arg0 == 0:  # PTRACE_TRACEME
        t.syscall_return = 0  # pretend success

d.handle_syscall("ptrace", on_exit=fake_ptrace)
```

---

## GDB Migration

Switch to GDB mid-session for interactive inspection, then return to libdebug:

```python
# Blocking — opens GDB, script waits until you quit GDB
d.gdb()

# In current terminal
d.gdb(open_in_new_process=False)

# Non-blocking — script continues while GDB runs
d.gdb(blocking=False)
d.wait_for_gdb()

# Migrate breakpoints to GDB
d.gdb(migrate_breakpoints=True)

# Set terminal for new-process mode
from libdebug import libcontext
libcontext.terminal = ['tmux', 'splitw', '-h']
```

GDB migration is useful when you need GDB's interactive features (disassembly view, TUI mode) for a specific section of analysis, while keeping the scripted automation of libdebug for everything else.
