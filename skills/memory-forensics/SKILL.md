---
name: memory-forensics
description: >
  Analyze memory dump files using Volatility 3 and mquire. Use this skill
  whenever the user has a memory dump (.raw, .mem, .vmem, .dmp, .lime, .elf)
  and wants to analyze it — extract processes, network connections, files,
  registry keys, credentials, or investigate system state. Also trigger when
  the user mentions memory forensics, memdump analysis, volatility, mquire,
  RAM analysis, "analyze this memory image", "what processes were running",
  "extract files from memory", or any task involving memory dump analysis.
  Trigger on any mention of volatility plugins (pslist, netscan, filescan,
  malfind, hashdump, etc.) or memory forensics techniques.
---

# Memory Forensics Skill

Analyze memory dumps using **Volatility 3** (primary) with **mquire** as
fallback for Linux images missing symbol tables.

All analysis artifacts go into `output/` relative to the working directory.

## Step 1: Preparation

Determine the volatility command:

```bash
if command -v vol &>/dev/null; then
  VOL="vol"
else
  VOL="python3 -m volatility3.cli"
fi
```

```bash
mkdir -p output
DUMP="<path-to-memdump>"
```

## Step 2: Strings Extraction

Extract strings before running Volatility — it's fast and provides raw
material for later searches.

```bash
# ASCII strings
strings "$DUMP" > output/strings_ascii.txt

# Little-endian UTF-16 strings (Windows wide strings)
strings -e l "$DUMP" > output/strings_utf16le.txt
```

Extract structured data from strings:

```bash
# URLs
grep -oE 'https?://[^\s"]+' output/strings_ascii.txt \
  > output/strings_urls.txt 2>/dev/null || true

# IP addresses
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' output/strings_ascii.txt \
  > output/strings_ips.txt 2>/dev/null || true

# Email addresses
grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' output/strings_ascii.txt \
  > output/strings_emails.txt 2>/dev/null || true

# Passwords, secrets, keys
grep -i -E "(password|passwd|secret|key|token|admin|root|login)" \
  output/strings_ascii.txt > output/strings_secrets.txt 2>/dev/null || true

# Base64-encoded blobs (>=20 chars to reduce noise)
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' output/strings_ascii.txt \
  > output/strings_base64_candidates.txt 2>/dev/null || true
```

## Step 3: Identify the Memory Image

```bash
$VOL -f "$DUMP" banners 2>/dev/null | tee output/banners.txt
$VOL -f "$DUMP" windows.info 2>/dev/null | tee output/os_info.txt
$VOL -f "$DUMP" linux.banners 2>/dev/null | tee -a output/os_info.txt
```

If all fail with symbol errors, jump to **Step 6 (mquire fallback)** for
Linux dumps.

Based on output, determine:
- **Windows** → use `windows.*` plugins
- **Linux** → use `linux.*` plugins (or mquire if symbols fail)

## Step 4: Core Volatility Analysis

Run plugins based on detected OS. Save every output to `output/`.

### 4a. Process Analysis

**Windows:**
```bash
$VOL -f "$DUMP" windows.pslist | tee output/pslist.txt
$VOL -f "$DUMP" windows.pstree | tee output/pstree.txt
$VOL -f "$DUMP" windows.cmdline | tee output/cmdline.txt
$VOL -f "$DUMP" windows.envars 2>/dev/null | tee output/envars.txt
```

**Linux:**
```bash
$VOL -f "$DUMP" linux.pslist | tee output/pslist.txt
$VOL -f "$DUMP" linux.pstree | tee output/pstree.txt
$VOL -f "$DUMP" linux.bash | tee output/bash_history.txt
$VOL -f "$DUMP" linux.elfs 2>/dev/null | tee output/elfs.txt
```

Look for suspicious processes — unusual names, odd parent-child relationships
(e.g., cmd.exe spawned from a browser), suspicious command-line arguments.

### 4b. Network Analysis

```bash
# Windows
$VOL -f "$DUMP" windows.netscan 2>/dev/null | tee output/netscan.txt
$VOL -f "$DUMP" windows.netstat 2>/dev/null | tee output/netstat.txt

# Linux
$VOL -f "$DUMP" linux.sockstat 2>/dev/null | tee output/sockstat.txt
```

Cross-reference IPs/ports with strings output for context.

### 4c. File Analysis

```bash
# Windows
$VOL -f "$DUMP" windows.filescan 2>/dev/null | tee output/filescan.txt

# Linux
$VOL -f "$DUMP" linux.pagecache.Files 2>/dev/null | tee output/filecache.txt
```

Filter for interesting file types:

```bash
grep -iE "\.(txt|doc|pdf|zip|png|jpg|flag|key|enc|secret|py|ps1|bat|exe)" \
  output/filescan.txt 2>/dev/null > output/interesting_files.txt || true
```

### 4d. Dump Files

```bash
mkdir -p output/dumped_files

# Windows — dump by virtual address from filescan
$VOL -f "$DUMP" windows.dumpfiles --virtaddr <ADDR> \
  -o output/dumped_files 2>/dev/null

# Dump a process's memory
$VOL -f "$DUMP" windows.memmap --pid <PID> --dump \
  -o output/dumped_files 2>/dev/null
```

### 4e. Registry Analysis (Windows)

```bash
$VOL -f "$DUMP" windows.registry.hivelist 2>/dev/null \
  | tee output/hivelist.txt
$VOL -f "$DUMP" windows.registry.printkey 2>/dev/null \
  | tee output/registry.txt
$VOL -f "$DUMP" windows.hashdump 2>/dev/null \
  | tee output/hashdump.txt
```

### 4f. Malware / Injection Detection

```bash
$VOL -f "$DUMP" windows.malfind 2>/dev/null | tee output/malfind.txt
$VOL -f "$DUMP" windows.hollowprocesses 2>/dev/null \
  | tee output/hollowprocesses.txt
$VOL -f "$DUMP" linux.malfind 2>/dev/null | tee output/malfind.txt
```

### 4g. Additional Plugins

```bash
# Clipboard (Windows)
$VOL -f "$DUMP" windows.clipboard 2>/dev/null | tee output/clipboard.txt

# MFT timeline
$VOL -f "$DUMP" windows.mftscan.MFTScan 2>/dev/null \
  | tee output/mftscan.txt

# DLLs for a specific process
$VOL -f "$DUMP" windows.dlllist --pid <PID> 2>/dev/null \
  | tee output/dlllist.txt

# Handles for a process
$VOL -f "$DUMP" windows.handles --pid <PID> 2>/dev/null \
  | tee output/handles.txt

# Kernel modules
$VOL -f "$DUMP" linux.lsmod 2>/dev/null | tee output/lsmod.txt
$VOL -f "$DUMP" windows.modules 2>/dev/null | tee output/modules.txt
$VOL -f "$DUMP" windows.driverscan 2>/dev/null | tee output/driverscan.txt

# Services (Windows)
$VOL -f "$DUMP" windows.svcscan 2>/dev/null | tee output/svcscan.txt

# Scheduled tasks
$VOL -f "$DUMP" windows.scheduled_tasks 2>/dev/null \
  | tee output/sched_tasks.txt
```

## Step 5: Targeted Investigation

After core analysis, drill into findings:

1. **Suspicious process** → dump memory, extract strings, check DLLs/handles
2. **Interesting file** → dump it, run `file`, inspect content
3. **Odd network connection** → correlate with process, check strings
4. **Encoded data** → try base64, XOR, look for crypto keys in process memory

Process-specific string extraction:

```bash
$VOL -f "$DUMP" windows.memmap --pid <PID> --dump -o output/dumped_files
strings output/dumped_files/pid.<PID>.dmp > output/pid_<PID>_strings.txt
```

## Step 6: mquire (Linux Only)

When Volatility fails with symbol errors on a Linux dump, use mquire first.
mquire uses BTF data embedded in the kernel (4.18+), needing no external
symbols — no downloads, no waiting.

```bash
MQUIRE="${HOME}/.cargo/bin/mquire"
if ! command -v mquire &>/dev/null && [ -x "$MQUIRE" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
```

mquire uses SQL queries:

```bash
# System info
mquire -f "$DUMP" -c "SELECT * FROM system_info;" \
  | tee output/mquire_sysinfo.txt

# Process list
mquire -f "$DUMP" -c "SELECT pid, ppid, comm, state FROM tasks;" \
  | tee output/mquire_pslist.txt

# Open files per process
mquire -f "$DUMP" \
  -c "SELECT t.pid, t.comm, f.path FROM tasks t JOIN open_files f ON t.pid = f.pid;" \
  | tee output/mquire_open_files.txt

# Network connections
mquire -f "$DUMP" -c "SELECT * FROM net_connections;" \
  | tee output/mquire_netstat.txt

# Kernel modules
mquire -f "$DUMP" -c "SELECT * FROM modules;" \
  | tee output/mquire_modules.txt

# Kernel log (dmesg)
mquire -f "$DUMP" -c "SELECT * FROM dmesg;" \
  | tee output/mquire_dmesg.txt

# Memory mappings for a process
mquire -f "$DUMP" \
  -c "SELECT * FROM memory_mappings WHERE pid = <PID>;" \
  | tee output/mquire_maps.txt

# File recovery from page cache
mquire -f "$DUMP" -c "SELECT * FROM cached_files;" \
  | tee output/mquire_cached_files.txt

# Process tree
mquire -f "$DUMP" --pstree | tee output/mquire_pstree.txt
```

The SQL interface is flexible — JOIN tables, filter with WHERE, aggregate
as needed for the investigation.

## Step 7: Linux Symbol Tables Fallback

If mquire also fails (e.g., kernel older than 4.18 without BTF), download
the matching Volatility symbol table from the community repository:

https://github.com/Abyss-W4tcher/volatility3-symbols/

Find the JSON symbol file matching the kernel version (from `banners` output),
download it, and place it in the Volatility symbols directory:

```bash
# Find where Volatility looks for symbols
VOL_SYMBOLS=$(python3 -c "import volatility3.symbols; import os; print(os.path.dirname(volatility3.symbols.__file__))")

# Download and install the matching symbol table
cp <downloaded-symbol-file>.json.xz "$VOL_SYMBOLS/linux/"
```

Then retry the failed Volatility `linux.*` commands — they should now
resolve the symbol table automatically.
