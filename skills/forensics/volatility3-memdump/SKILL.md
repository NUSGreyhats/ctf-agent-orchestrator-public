---
name: volatility3-memdump
description: >
  Use ONLY for full-system memory dumps (.lime, .raw, .mem, .vmem, full
  Windows crashdump) where the analysis requires Volatility 3 plugin syntax —
  the namespacing the model habitually gets wrong (`windows.pslist.PsList`,
  `linux.pslist.PsList`, `windows.malfind.Malfind`, etc.) — or Linux symbol
  generation via dwarf2json for custom kernels. Also use for mquire as a
  fallback when Vol3 symbol lookup fails. Skip this skill for single-process
  minidumps (gcore output, procdump for one PID — use gdb on the corefile
  instead), for ARM/Apple Silicon dumps where Vol3 support is patchy, and
  whenever `strings dump | grep -aE 'flag\{'` already reveals the answer —
  try the cheap path first.
---

# Volatility 3 Memdump Analysis

Recipes for full-system memory dumps. **Always run `strings -a dump | grep -aE 'flag\{'` first** — it solves a meaningful fraction of memory CTFs in seconds. The recipes below are only worth running once the cheap path fails.

All artifacts go into `output/`.

```bash
mkdir -p output
DUMP="<path-to-memdump>"
VOL=$(command -v vol &>/dev/null && echo "vol" || echo "python3 -m volatility3.cli")
```

For large sparse dumps, keep offsets while searching:

```bash
LC_ALL=C grep -aobE 'flag\{|CTF\{|key|token|password' "$DUMP" | head -300 \
  | tee output/interesting_offsets.txt
strings -a -td "$DUMP" | grep -iE 'flag|key|token|password' | head -300 \
  | tee output/interesting_strings_offsets.txt
```

Inspect nearby bytes before treating a string hit as recoverable file content.

## Identify the OS

The trip-up: Vol3 plugin namespace is `windows.*` vs `linux.*` and you must pick the right one — running `windows.pslist.PsList` on a Linux dump silently returns nothing.

```bash
$VOL -f "$DUMP" banners 2>/dev/null | tee output/banners.txt
$VOL -f "$DUMP" windows.info 2>/dev/null
$VOL -f "$DUMP" linux.banners 2>/dev/null
```

If all fail with `SymbolError`, jump to the **Symbol fallback** section below before retrying.

## Vol3 plugin syntax (the namespacing trip-up)

Plugins are dotted-path classes — common ones:

| Goal | Windows | Linux |
|---|---|---|
| Process list | `windows.pslist.PsList` (or just `windows.pslist`) | `linux.pslist.PsList` |
| Process tree | `windows.pstree` | `linux.pstree` |
| Cmdlines | `windows.cmdline` | `linux.psaux` |
| Env vars | `windows.envars` | — |
| Bash history | — | `linux.bash` |
| Network connections | `windows.netscan`, `windows.netstat` | `linux.sockstat` |
| File listing in memory | `windows.filescan` | `linux.pagecache.Files` |
| Dump a process | `windows.memmap --pid <PID> --dump` | `linux.proc.Maps --pid <PID>` |
| Dump a file | `windows.dumpfiles --virtaddr <ADDR>` | `linux.pagecache.RecoverFs` |
| Code injection | `windows.malfind` | `linux.malfind` |
| Process hollowing | `windows.hollowprocesses` | — |
| Loaded modules | `windows.modules`, `windows.driverscan` | `linux.lsmod` |
| Services | `windows.svcscan` | — |
| Registry hives | `windows.registry.hivelist` | — |
| Registry key dump | `windows.registry.printkey --key 'Software\...'` | — |
| Password hashes | `windows.hashdump` | — |
| Clipboard | `windows.clipboard` | — |
| MFT scan | `windows.mftscan.MFTScan` | — |
| Open handles | `windows.handles --pid <PID>` | `linux.lsof` |
| DLLs / shared libs | `windows.dlllist --pid <PID>` | `linux.library_list` |

Run with `-o output/` to direct dumped artifacts to the output directory:

```bash
$VOL -f "$DUMP" -o output/ windows.dumpfiles --virtaddr 0x... 
$VOL -f "$DUMP" -o output/ windows.memmap --pid 1234 --dump
```

## Symbol fallback for Linux dumps

Vol3 needs a symbol table matching the kernel exactly. If `linux.banners` works but `linux.pslist` reports `SymbolError`, the kernel is recognized but no matching symbol JSON is installed.

### Option 1 — community symbol repo

The maintained mirror is https://github.com/Abyss-W4tcher/volatility3-symbols/. Find the JSON matching the kernel version from the banner:

```bash
VOL_SYMBOLS=$(python3 -c "import volatility3.symbols, os; print(os.path.dirname(volatility3.symbols.__file__))")
# Place the matching .json.xz file here:
cp <downloaded>.json.xz "$VOL_SYMBOLS/linux/"
```

### Option 2 — generate from source with dwarf2json

For custom or stripped kernels:

```bash
# Need: vmlinux with debug info, plus System.map (or kallsyms output)
git clone --depth 1 https://github.com/volatilityfoundation/dwarf2json /tmp/d2j
cd /tmp/d2j && go build && cd -
/tmp/d2j/dwarf2json linux \
  --elf /path/to/vmlinux \
  --system-map /path/to/System.map \
  > "$VOL_SYMBOLS/linux/$(uname -r).json"
```

### Option 3 — mquire (BTF-based, no external symbols)

mquire reads BTF data embedded in the kernel image (Linux 4.18+) — no downloads. Use when Vol3 symbol generation is impractical.

```bash
mquire -f "$DUMP" -c "SELECT * FROM system_info;"
mquire -f "$DUMP" -c "SELECT pid, ppid, comm, state FROM tasks;"
mquire -f "$DUMP" -c "SELECT t.pid, t.comm, f.path FROM tasks t JOIN open_files f ON t.pid = f.pid;"
mquire -f "$DUMP" -c "SELECT * FROM net_connections;"
mquire -f "$DUMP" -c "SELECT * FROM modules;"
mquire -f "$DUMP" -c "SELECT * FROM dmesg;"
mquire -f "$DUMP" -c "SELECT * FROM cached_files;"
mquire -f "$DUMP" --pstree
```

The schema is SQL — JOIN/WHERE/aggregate as needed. Tables include `tasks`, `open_files`, `net_connections`, `modules`, `dmesg`, `memory_mappings`, `cached_files`, `system_info`.

## Targeted process dump and analysis

```bash
# Dump a process's pages then strings the result
mkdir -p output/pid_dump
$VOL -f "$DUMP" -o output/pid_dump windows.memmap --pid <PID> --dump
strings output/pid_dump/pid.<PID>.dmp > output/pid_<PID>_strings.txt
```

For credential extraction, `windows.hashdump` produces SAM hashes and `windows.lsadump` extracts LSA secrets. For RDP/TS sessions, `windows.cachedump` hits MSCACHE creds.

## Common CTF wins

- **Bash history on Linux** → `linux.bash` (recovers commands directly from memory).
- **Clipboard contents on Windows** → `windows.clipboard`.
- **Hidden processes** → diff `windows.pslist` against `windows.psscan`; entries in psscan-only are likely DKOM-hidden.
- **Injected code** → `windows.malfind` flags RWX private allocations; dump with `--dump` and run `strings`/disassembly on the result.
- **Recently-edited file content** → `windows.filescan` to find the `_FILE_OBJECT` virtual address, then `windows.dumpfiles --virtaddr <ADDR>` extracts the cached pages.
- **MFT hits are metadata first** → `windows.mftscan.MFTScan` can show a
  filename even when `$DATA` is zero-length or nonresident bytes are absent.
  Verify `$DATA` length/runlists before claiming file recovery.
