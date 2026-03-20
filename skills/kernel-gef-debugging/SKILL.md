---
name: kernel-gef-debugging
description: Debug Linux kernels using bata24/GEF (GDB Enhanced Features) via the GDB MCP. Use when doing kernel debugging, exploit development, slab/heap inspection, task/cred analysis, memory layout investigation, ROP gadget search, or any qemu-system kernel GDB session. Trigger on kernel debugging, GEF commands, slab analysis, task_struct, cred struct, pagetable, KASLR, kmalloc, SLUB, page tables, or kernel exploit development.
model: sonnet
---

# Kernel Debugging with bata24/GEF

GEF is installed at `/opt/gef/gef.py`. Load it when starting a GDB session:

```
gdb_start(binary="vmlinux_path", remote="localhost:1234", init_script="/opt/gef/gef.py")
```

After loading, all GEF commands work via `gdb_exec("command")`.

## Setup Notes

- The GDB MCP uses `-nx` (no gdbinit). GEF must be loaded via `init_script` parameter.
- The MCP auto-configures GEF for non-interactive use:
  - `gef config gef.disable_color True` — no ANSI escape codes in output
  - `gef config context.enable False` — suppresses the noisy register/stack/code context on every stop
- GEF works with QEMU `-s` (GDB stub on port 1234). No special kernel config needed.
- Most kernel commands work WITHOUT debug symbols — they scan memory directly.
- Supports Linux kernels 3.x through 6.19.x.
- To temporarily re-enable context display: `gdb_exec("gef config context.enable True")`

## Qemu-System: Memory & Address Translation

| Command | What it does |
|---------|-------------|
| `pagewalk x64` | Dump x86_64 page tables (4-level/5-level paging) |
| `v2p <vaddr>` | Virtual → physical address translation |
| `p2v <paddr>` | Physical → virtual address translation |
| `xp <addr>` | Physical memory dump (shortcut) |
| `page <addr>` | Transform between struct page and virtual/physical address |
| `page to_phys <virt>` | Virtual → physical |
| `page to_virt <phys>` | Physical → virtual |
| `page from_phys <phys>` | Physical → struct page |
| `page from_virt <virt>` | Virtual → struct page |
| `virt2page` / `page2virt` / `phys2page` / `page2phys` | Shortcuts for above |
| `pageinfo <addr>` | Dump struct page flags and page_type |
| `kvmmap` | Kernel virtual memory map (all regions) |
| `vmalloc-dump` | Dump vmalloc used-list and freed-list |
| `xinfo <addr>` | Detailed info about any address (region, permissions, symbol) |

## Qemu-System: Kernel Basic Info

| Command | What it does |
|---------|-------------|
| `kbase` | Kernel base address (works with KASLR) |
| `kversion` | Kernel version string |
| `kcmdline` | Boot command line |
| `kcurrent` | Current task_struct address for each CPU |
| `kchecksec` | Kernel security checks (SMEP, SMAP, KASLR, KPTI, stack canary, etc.) |
| `kmagic` | Useful kernel addresses (commit_creds, init_cred, modprobe_path, etc.) |
| `kconfig` | Dump kernel .config if available |
| `kdmesg` | Dump dmesg ring buffer |
| `qreg` | Register values from qemu-monitor (includes system registers) |
| `sysreg` | Pretty-print system registers (CR0, CR3, CR4, EFER, etc.) |
| `msr` | Read/write MSR values via dynamic assembly (x64/x86) |

## Qemu-System: Symbol Resolution (no debug symbols needed)

| Command | What it does |
|---------|-------------|
| `ksymaddr-remote` | Scan kernel memory to reconstruct kallsyms (3.x-6.19.x) |
| `ksymaddr-remote-apply` | Apply discovered kallsyms to GDB session |
| `vmlinux-to-elf-apply` | Apply vmlinux-to-elf symbols to GDB |
| `ktypes` | Display kernel type info from memory scanning |
| `ktypes-load` | Load kernel type info into GDB |
| `kload` | Load vmlinux without needing load address |

## Qemu-System: SLUB / SLAB / Allocator Inspection

| Command | What it does |
|---------|-------------|
| `slub-dump` | Dump SLUB freelists (works with KASLR, no symbols, hardened freelist) |
| `slub-dump <name>` | Dump specific cache (e.g., `slub-dump kmalloc-1024`) |
| `slub-dump -v` | Include partial pages |
| `slub-dump -vv` | Include NUMA node pages |
| `slab-dump` | Dump SLAB freelists |
| `slub-tiny-dump` | Dump SLUB-TINY freelists |
| `slab-contains <addr>` | Find which kmem_cache an address belongs to |
| `kmem-cache-alias` | Show kmem_cache merge aliases (which caches share slabs) |
| `slab-virtual` | Transform between slab metadata and slab data address |
| `buddy-dump` | Dump buddy allocator (page allocator) freelists by zone |
| `kmalloc-tracer` | Trace kmalloc/kfree calls at runtime |
| `kmalloc-allocated-by` | Run syscalls and show which kmalloc caches they use |

## Qemu-System: Task / Process Inspection

| Command | What it does |
|---------|-------------|
| `ktask` | List all tasks with addresses |
| `ktask -q` | Quiet — just addresses and names |
| `ktask -u` | Show userland memory maps |
| `ktask -r` | Show saved registers (from kstack) |
| `ktask -f` | Show open file descriptors |
| `ktask -s` | Show signal handlers |
| `ktask -n` | Show namespaces |
| `ktask --seccomp` | Show seccomp filters |
| `kfiles` | Shortcut: `ktask -quf` |
| `kregs` | Shortcut: `ktask -qur` |
| `ksighands` | Shortcut: `ktask -qus` |
| `knamespaces` | Shortcut: `ktask -qun` |

## Qemu-System: Kernel Subsystems

| Command | What it does |
|---------|-------------|
| `kops` | Display operation struct members (file_operations, etc.) |
| `kmod` | List loaded modules with addresses and symbols |
| `kmod-load` | Load kernel module symbols into GDB |
| `kcdev` | Character device information |
| `kbdev` | Block device information |
| `kfilesystems` | Supported filesystems |
| `kclock-source` | Clocksource list |
| `kpipe` | Pipe information |
| `kbpf` | BPF programs and maps |
| `ktimer` | Timer information |
| `kpcidev` | PCI devices |
| `kipcs` | IPC info (System V semaphore, message queue, shared memory) |
| `kdevio` | I/O port and I/O memory info |
| `kdmabuf` | DMA-BUF info |
| `kirq` | IRQ information |
| `knetdev` | Network devices |
| `ksysctl` | Sysctl parameters |
| `syscall-table-view` | System call table (includes ia32/x32 on x64) |

## Qemu-System: Kernel Exploit Development

| Command | What it does |
|---------|-------------|
| `ksearch-code-ptr` | Search for code pointers in kernel data area |
| `thunk-tracer` | Collect thunk function addresses called automatically (x64/x86). Useful for finding RIP control from RW areas |
| `usermodehelper-tracer` | Trace call_usermodehelper_setup invocations |
| `ktrace` | Trace kernel functions and arguments |
| `ropper` | Search ROP gadgets via rp++ v2 (x64/x86) |
| `search-cfi-gadgets` | Search CFI-valid (CET IBT) controllable gadgets |
| `find-syscall` | Search for syscall gadgets |

## Improved Standard Commands (kernel-aware)

| Command | What it does |
|---------|-------------|
| `search-pattern <pat>` | Search memory for pattern. Works under qemu-system without /proc. Options: `--hex`, `--hex-regex`, `--aligned`, `--perm`, `--phys`, `--limit` |
| `hexdump` | Supports physical memory under qemu-system. Omits repeated lines by default |
| `patch` | Supports physical memory. Sub-commands: `hex`, `nop`, `ret`, `trap`, `syscall`, `pattern`, `range-replace`, `history`, `revert` |
| `telescope` | Enhanced: shows canaries, return addresses, symbols. Options: `--phys`, `--list-head`, `--slab-contains`, `--slab-contains-unaligned`, `--uniq`, `--interval`, `--depth` |
| `xinfo <addr>` | Shows detailed info, supports kernel addresses |
| `vmmap` | Redirected to `kvmmap` under qemu-system |
| `walk-link-list <addr>` | Walk Linux kernel linked lists (list_head) |
| `memcmp` / `memset` / `memcpy` / `memswap` | Work with both virtual and physical memory |
| `dt <type> [addr]` | Pretty-print kernel struct with offsets (like pahole). Auto-adjusts max-value-size |
| `seccomp` | Invoke seccomp-tools |
| `onegadget` | Invoke one_gadget |

## Common Workflows

### Find current task's cred address
```
gdb_exec("kcurrent")
gdb_exec("p/x ((struct task_struct *)ADDR)->cred")
gdb_exec("p/x *((struct cred *)CRED_ADDR)")
```

### Get all important exploit addresses at once
```
gdb_exec("kmagic")    # commit_creds, init_cred, modprobe_path, core_pattern, etc.
```

### Inspect slab layout around an object
```
gdb_exec("slab-contains 0xffff888012345678")
gdb_exec("slub-dump kmalloc-1024")
gdb_exec("kmem-cache-alias")          # check for merged caches
```

### Find kernel addresses without vmlinux symbols
```
gdb_exec("ksymaddr-remote")           # reconstruct kallsyms from memory
gdb_exec("ksymaddr-remote-apply")     # apply to GDB for symbol resolution
```

### Check kernel mitigations
```
gdb_exec("kchecksec")
```

### Search kernel memory for a byte pattern
```
gdb_exec("search-pattern --hex e8030000e8030000")   # uid=1000,gid=1000
gdb_exec("search-pattern 0xdeadbeef")
```

### Dump page tables for an address
```
gdb_exec("pagewalk x64")
gdb_exec("v2p 0xffff888012345678")
```

### Trace kmalloc/kfree to understand heap layout
```
gdb_exec("kmalloc-tracer")            # sets breakpoints, then continue
gdb_exec("kmalloc-allocated-by")      # shows which syscalls allocate what
```

### Walk a kernel linked list
```
gdb_exec("walk-link-list 0xffff888012345678")
```

### Inspect BPF state
```
gdb_exec("kbpf")
```

### Find ROP gadgets
```
gdb_exec("ropper -- --search 'pop rdi; ret'")
gdb_exec("search-cfi-gadgets")
```

### Dump struct with offsets (like pahole)
```
gdb_exec("dt struct cred")
gdb_exec("dt struct cred 0xffff888012345678")
```
