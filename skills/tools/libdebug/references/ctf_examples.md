# Real-World CTF Examples

Complete solutions from CTF competitions demonstrating libdebug patterns. Read these when solving challenges that match these patterns.

## Table of Contents

1. [Pattern: Side-Channel Brute-Force](#side-channel-brute-force)
2. [Pattern: Register Manipulation at Breakpoint](#register-manipulation-at-breakpoint)
3. [Pattern: Execution Flow Hijacking](#execution-flow-hijacking)
4. [Pattern: Anti-Debug + Syscall Bypass](#anti-debug--syscall-bypass)
5. [Pattern: Multi-Stage with Bitmap Decoding](#multi-stage-with-bitmap-decoding)

---

## Side-Channel Brute-Force

**When to use**: The binary validates input character-by-character and takes a different code path (more iterations, different timing) for correct characters.

**Strategy**: For each character position, try all candidates. Count breakpoint hits at the comparison point. The correct character produces more hits.

```python
from libdebug import debugger
from string import ascii_letters, digits

d = debugger("main", escape_antidebug=True)

def callback(_, __):
    pass  # empty callback = auto-continue (just count hits)

def on_enter_nanosleep(t, _):
    # Null out all args to make nanosleep fail instantly
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

alphabet = ascii_letters + digits + "_{}"
flag = b""
best_hit_count = 0

while True:
    for c in alphabet:
        r = d.run()
        # Breakpoints must be re-set after each run()
        bp = d.breakpoint(0x13e1, hardware=True, callback=callback, file="binary")
        d.handle_syscall("clock_nanosleep", on_enter=on_enter_nanosleep)
        d.cont()
        r.sendline(flag + c.encode())
        d.wait()
        response = r.recvline()
        d.kill()

        if b"Yeah" in response:
            flag += c.encode()
            print(flag)
            break

        if bp.hit_count > best_hit_count:
            best_hit_count = bp.hit_count
            flag += c.encode()
            print(flag)
            break

    if c == "}":
        break

print(flag)
```

**Key techniques**:
- `escape_antidebug=True` for ptrace detection bypass
- `callback=callback` (empty) for async breakpoints — just count, don't stop
- Syscall handler to skip `nanosleep` delays (speeds up brute-force)
- Re-set breakpoints after each `d.run()` — they don't persist

---

## Register Manipulation at Breakpoint

**When to use**: The binary compares user input against an expected value in registers. You can read the expected value and compute the correct input.

**Strategy**: Break at the comparison, read the expected value from registers, XOR/subtract to recover the correct character.

```python
from libdebug import debugger

def get_passphrase_from_class_3():
    flag = b""
    d = debugger("CTF/0")
    r = d.run()
    bp = d.breakpoint(0x91A1, hardware=True, file="binary")
    d.cont()

    r.send(b"a" * 8)  # send known input

    for _ in range(8):
        if not bp.hit_on(d):
            print("Expected breakpoint hit")

        # Recover the offset between our input and expected
        offset = ord("a") - d.regs.rbp
        d.regs.rbp = d.regs.r13  # fix comparison to pass

        # Compute correct character
        flag += chr((d.regs.r13 + offset) % 256).encode("latin-1")
        d.cont()

    r.recvline()
    d.kill()
    return flag
```

**Key techniques**:
- Send known input ("aaa...") so you can compute the delta
- Read expected values from registers at comparison point
- Patch registers (`d.regs.rbp = d.regs.r13`) to force the check to pass
- Continue to the next comparison

---

## Execution Flow Hijacking

**When to use**: You need to force the binary to execute a function it wouldn't normally reach (e.g., a display function, a flag printer).

**Strategy**: Break early in the program, modify RIP to jump to the target function.

```python
from libdebug import debugger

d = debugger("./chall")
pipe = d.run()

# Break at a known point in play()
bp = d.breakpoint("play()+26", file="binary", hardware=True)

while not d.dead:
    d.cont()
    d.wait()

    if bp.hit_on(d.threads[0]):
        d.step()
        # Redirect to displayBoard function
        d.regs.rip = d.maps[0].base + 0x2469
        break

# Now read the board state from stdout
pipe.recvline(numlines=4)
board_data = pipe.recvline(25).decode().strip().split(" ")

# ... process data, solve puzzle, send solution ...
d.terminate()
```

**Key techniques**:
- Symbol + offset syntax: `"play()+26"` (parentheses are part of the symbol name)
- Use `d.maps[0].base` for binary base address (when ASLR is on)
- `d.step()` after breakpoint before modifying RIP
- Check `d.dead` in loops to handle process exit

---

## Anti-Debug + Syscall Bypass

**When to use**: Binary uses anti-debugging (ptrace checks) AND time-based delays to slow down analysis.

**Strategy**: Combine `escape_antidebug=True` with syscall handlers that neutralize delay functions.

```python
from libdebug import debugger

d = debugger("./protected", escape_antidebug=True)
io = d.run()

# Skip nanosleep — zero out all arguments
def skip_sleep(t, _):
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0

d.handle_syscall("clock_nanosleep", on_enter=skip_sleep)
d.handle_syscall("nanosleep", on_enter=skip_sleep)

d.cont()
flag = io.recvuntil(b"}", timeout=5)
print(flag.decode())
d.terminate()
```

---

## Multi-Stage with Bitmap Decoding

**When to use**: The binary validates characters through multiple stages with different algorithms. Each stage may use lookup tables, bitmaps, or other transformations.

**Strategy**: Use multiple breakpoints to intercept each stage. Build lookup tables from observed register values.

```python
from libdebug import debugger

def solve_stage_2(previous_flag):
    bitmap = {}
    lastpos = 0
    flag = b""

    d = debugger("CTF/2")
    r = d.run()

    # Three breakpoints for three phases of the algorithm
    bp1 = d.breakpoint(0xD8C1, hardware=True, file="binary")
    bp2 = d.breakpoint(0x1858, hardware=True, file="binary")
    bp3 = d.breakpoint(0xDBA1, hardware=True, file="binary")

    d.cont()
    r.recvuntil(b"Passphrase:\n")
    r.send(previous_flag + b"a" * 8)

    while True:
        if d.regs.rip == bp1.address:
            # Phase 1: Record position for bitmap
            lastpos = d.regs.rbp
            d.regs.rbp = d.regs.r13 + 1
        elif d.regs.rip == bp2.address:
            # Phase 2: Build lookup bitmap
            bitmap[d.regs.r12 & 0xFF] = lastpos & 0xFF
        elif d.regs.rip == bp3.address:
            # Phase 3: Use bitmap to decode expected character
            d.regs.rbp = d.regs.r13
            wanted = d.regs.rbp
            needed = 0
            for i in range(8):
                if wanted & (2**i):
                    needed |= bitmap[2**i]
            flag += chr(needed).encode()

            if bp3.hit_count == 8:
                d.cont()
                break

        d.cont()

    d.kill()
    return flag
```

**Key techniques**:
- Multiple hardware breakpoints at different algorithm phases
- Build data structures (bitmap) from observed register values
- Use `d.regs.rip == bp.address` to determine which breakpoint fired (alternative to `hit_on()` when multiple bps are synchronous)
- Patch registers to make each phase pass while extracting the expected values
- Chain stages: output of one stage feeds into the next
