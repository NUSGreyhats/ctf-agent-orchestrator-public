---
name: ctf-methodology
description: >
  Entrypoint for solving CTF challenges. Covers triage, flag searching,
  and routes to the correct skill.
---

# CTF Methodology

## Step 1: Determine the Flag Format

Read the challenge description. Determine the expected answer format
(e.g., `flag{...}`, `CTF{...}`, a specific value). If unclear, ask.

## Step 2: Quick Flag Search

Run `ctfgrep` first. It searches plaintext, base64, hex, and XOR:

```bash
ctfgrep -i <directory> "flag{"
```

## Step 3: Triage and Load Skills

Triage files (`file`, `exiftool`, `strings`, `binwalk`), then load the
relevant skill **before** deeper analysis.

| Category | Skill |
|---|---|
| Cryptography | `ctf-crypto` |
| Binary exploitation | `ctf-pwn` |
| Reverse engineering | `ctf-reverse` |
| Web exploitation | `ctf-web` |
| Mixed / unclear | `ctf-misc` |
| OSINT | `ctf-osint` |
| Malware analysis | `ctf-malware` |
| AI/ML challenges | `ctf-ai-ml` |
| Forensic-format disk image or Sleuth Kit recovery | `tsk-disk-recovery` |
| Corrupted file, steganography, Office/PDF dissection | `file-repair-and-stego` |
| Full-system memory dump | `volatility3-memdump` |
| Packet capture extraction | `pcap-extraction` |

Load tool skills when needed:

| Tool | Skill |
|---|---|
| IDA Pro | `analyze-with-ida-domain-api` |
| GDB + GEF | `kernel-gef-debugging` |
| APK analysis | `apk-analysis` |

Load multiple skills if the challenge spans categories.

## Step 4: Work Methodically

- **Maintain your working notes file** (exact filename is in your
  prompt). Record what you tried and found. Your context may be
  compacted; the notes file survives. Re-read it if you lose context.
- **Keep notes decision-oriented.** For each path, record the evidence,
  hypothesis, test result, and the next targeted check.
- **Never suppress stderr** (`2>/dev/null`). Use `2>&1` instead.
- **Correlate across artifacts.** Cross-reference usernames, IPs,
  timestamps between different sources.
- **Re-read the description** when stuck — hints become obvious after
  exploring the data.
- **Decoy flags mean dig deeper** in the same artifact.
- **Diff against known originals** when a challenge contains a
  published file — flags hide in format-specific fields that string
  searches miss.
