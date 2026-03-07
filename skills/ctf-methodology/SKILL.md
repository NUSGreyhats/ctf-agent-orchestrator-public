---
name: ctf-methodology
description: >
  Methodology for solving CTF challenges. Use this skill whenever the user is
  working on a CTF challenge — forensics, reverse engineering, crypto, web,
  misc, or any category. Trigger when the user mentions CTF, capture the flag,
  flag format, "find the flag", challenge descriptions, or is clearly working
  through a competition challenge. Also trigger when the user pastes a
  challenge description, mentions a flag format like flag{}, CTF{}, HTB{},
  picoCTF{}, or asks to analyze a file in a CTF context. This skill covers
  the thinking process and search techniques — it complements domain-specific
  skills (memory-forensics, apk-analysis, etc.) that handle the actual tools.
---

# CTF Methodology

This skill covers how to think about and approach CTF challenges. It focuses
on the process of finding flags — the domain-specific skills handle the tools.

## Step 1: Know What You're Looking For

Before touching any tool, establish the **target**:

1. **Read the challenge description carefully.** It almost always contains
   hints — specific programs, filenames, users, techniques, or encodings.

2. **Determine the answer format.** There are two cases:
   - **Flag with a known format** — e.g., `flag{...}`, `CTF{...}`, `HTB{...}`,
     `picoCTF{...}`. If not explicitly stated, ask the user to confirm the
     flag format before proceeding.
   - **Specific answer without a flag format** — some challenges ask for a
     timestamp, a PID, a filename, an IP address, a hash, etc. The answer is
     the value itself. Read the question carefully to know exactly what form
     the answer should take.

3. **If no flag format is stated and the challenge doesn't ask a specific
   question**, assume there is a flag and ask the user to clarify the format.
   Common formats: `flag{...}`, `FLAG{...}`, `ctf{...}`. Getting this right
   early saves wasted grep cycles.

## Step 2: Quick Flag Search with ctfgrep

When given a static file or directory to analyze, the fastest first step is
to search directly for the flag across multiple encodings. The flag might be
hidden in base64, hex, or even single-byte XOR — not just plaintext.

Use `ctfgrep` which searches for a string simultaneously across **plaintext,
base64, hex, and single-byte XOR encodings**. It's multithreaded and recursive.

### Usage

```bash
# Search a directory for a flag prefix across all encodings
ctfgrep -i <directory> "flag{"

# Search with shorter minimum encoded length (default 8)
ctfgrep -i -m 4 <directory> "HTB{"

# Search a single file's strings output
strings <file> > /tmp/strings_out.txt
mkdir /tmp/strings_dir && mv /tmp/strings_out.txt /tmp/strings_dir/
ctfgrep -i /tmp/strings_dir "picoCTF{"
```

ctfgrep reports which encoding the match was found in (PLAINTEXT, BASE64,
HEX, or XOR with the key), along with the decoded content. This catches
flags that are trivially obfuscated — a very common CTF technique.

## Step 3: Triage by Challenge Category

After the quick search, approach the challenge based on its category.
Each section below references the dedicated skill to use — invoke it
for the full methodology and tool commands.

### Forensics (memory dumps)
**Skill:** `memory-forensics`
- Strings triage first (already part of that skill)
- Identify OS, run volatility plugins (pslist, netscan, filescan, malfind)
- For Linux dumps without symbols: try mquire first, then download symbols
- Focus on processes, files, network, and registry

### Forensics (disk images)
**Skill:** `disk-forensics`
- Identify partitions with `mmls`, inspect filesystems with `fsstat`
- List and recover files with `fls`/`icat`/`tsk_recover`
- Carve unallocated space with `foremost`/`photorec`
- Run `bulk_extractor` for emails, URLs, credit cards, etc.
- Build a timeline with `fls -m` + `mactime`

### Forensics (files — steganography, PDFs, OLE docs, corrupted files)
**Skill:** `file-forensics`
- `file` + `exiftool` + `strings` + `binwalk` for initial triage
- Steganography: `zsteg` (PNG/BMP LSB), `steghide`/`stegseek` (JPEG/WAV)
- PDF analysis: `pdf-id.py`, `pdf-parser.py`, `cpdf`
- OLE/Office docs: `oleid`, `olevba`, `oledump.py`, `pcode2code`
- Corrupted files: repair magic bytes, fix structure

### Forensics (network captures)
**Skill:** `network-forensics`
- Protocol hierarchy and endpoint summary with `tshark`
- Extract HTTP objects: `tshark --export-objects http,output/`
- Follow and reconstruct TCP/UDP streams
- DNS analysis — tunneling detection, unusual queries
- Credential extraction from cleartext protocols
- File carving from reassembled streams with `tcpflow` + `foremost`
- TLS analysis — SNI, certificates, JA3 fingerprints

### Reverse Engineering
**Skills:** `headless-ida-domain-skill` (static), `libdebug-debugging` (dynamic)
- Static analysis with IDA: disassemble, decompile, xrefs, string analysis
- Dynamic analysis with libdebug: breakpoints, register/memory inspection,
  syscall tracing, anti-debug bypass
- Look for string comparisons, XOR loops, custom crypto

### Android RE
**Skill:** `apk-analysis`
- Decompile with `jadx`, decode resources with `apktool`
- Inspect AndroidManifest.xml, permissions, activities, services
- Search for hardcoded secrets, API keys, Firebase misconfigs
- Analyze native `.so` libraries with IDA

### Cryptography
- Identify the algorithm (RSA, AES, XOR, substitution, etc.)
- Check for weak parameters (small RSA modulus, ECB mode, reused nonces)
- Use standard tools: `openssl`, `python3` with pycryptodome, RsaCtfTool
- Use `z3-solver` or `sympy` for constraint-based problems

### Web
- Check source code, cookies, headers, robots.txt
- Test for injection (SQLi, XSS, SSTI, command injection)
- Check for exposed APIs, admin panels, backup files

### Misc / OSINT
- Read the description for hidden hints
- Google unusual strings, check metadata with `exiftool`
- Look for steganography, encoding puzzles, esoteric languages

## Step 4: Work Methodically

- **Never use `2>/dev/null`** on extraction tools. Many tools (steghide,
  stegseek, binwalk) print success/failure messages to stderr. Suppressing
  stderr makes you blind to whether extraction worked. Use `2>&1` instead.
- **Save everything.** Outputs go to `output/` — name files descriptively.
- **Document your path.** Note what you tried and what each step revealed.
  This avoids repeating dead ends and helps if you need to backtrack.
- **Correlate across artifacts.** A username from strings might appear in a
  process list. An IP from network connections might match a URL in a file.
  Cross-referencing is where flags often surface.
- **Re-read the challenge description** when stuck. Hints you missed the
  first time become obvious after you've explored the data.
- **Check for red herrings.** CTF authors sometimes plant decoys. If
  something looks too easy or doesn't quite match the flag format, verify it.
- **Decoy flags are hints, not dead ends.** If you find a flag that says
  "not the flag", "try harder", "this ain't it", etc. — the real flag is
  almost certainly hidden deeper in the **same artifact**. Apply additional
  extraction techniques (steganography, deeper layers, different encodings)
  to that file immediately.
- **Analyze extracted files immediately with quick checks.** When you
  extract files (e.g., images from a pcap, binaries from a disk image),
  run quick inline checks first: `exiftool`, `strings | grep flag`,
  `binwalk`, `steghide -p ""` (JPEG), `zsteg` (PNG). These take seconds
  and catch most common hiding techniques. If the quick checks don't find
  the flag and files need deeper analysis, **STOP and return your findings**
  to the caller — list each file and what deeper analysis it needs, so the
  caller can spawn dedicated subagents. (Subagents cannot spawn their own
  subagents — only the top-level agent has the Agent tool.)

## Step 5: Common Flag Hiding Techniques

| Technique | How to Find |
|---|---|
| Plaintext in file | `grep`, `strings`, ctfgrep |
| Base64 encoded | ctfgrep, or `grep -oE` + `base64 -d` |
| Hex encoded | ctfgrep, or `xxd -r -p` |
| Single-byte XOR | ctfgrep (tries all 256 keys) |
| ROT13 | `tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| In image metadata | `exiftool`, `strings` on the image |
| LSB steganography | `zsteg` (PNG/BMP), `steghide` (JPEG) |
| Embedded in binary | `strings`, `binwalk`, disassembly |
| In network traffic | `tshark`, follow streams, export objects |
| In memory dump | volatility process dump + strings |
| Split across files | Collect pieces, concatenate in order |
| URL / pastebin link | Fetch the URL from strings output |
| QR code in image | `zbarimg`, screenshot + decode |
| Whitespace encoding | Check for tabs/spaces patterns (stegsnow) |
| Zero-width chars | Check for Unicode zero-width joiners in text |
| Hidden in format fields | Diff against original; inspect non-text fields (colors, attributes, metadata) |

## Step 6: Diff Against Known Originals

When a challenge contains a **known file** (a published game, standard software,
well-known document), always diff the challenge version against the original
before doing deeper analysis. This is the single fastest way to find modifications.

- Download the original from an authoritative source (official site, archive.org,
  GitHub releases)
- Binary diff: `cmp -l original modified` or Python comparison
- For structured formats (game levels, save files, config): parse both and
  compare field-by-field — flags are often hidden in non-obvious fields like
  tile colors, attribute bytes, padding, or metadata that string searches miss
- A 141-byte size difference or a single modified board is far easier to spot
  in a diff than by searching blindly

This catches flags hidden in format-specific fields (e.g., ZZT tile color bytes,
ROM header padding, PNG ancillary chunks) that `grep`, `strings`, and `ctfgrep`
will never find because the flag isn't stored as a contiguous byte string.
