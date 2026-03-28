# Skills

Skills come from two sources:

1. **This repo** — methodology, forensics, and tool-specific skills
2. **[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)** — category skills (pwn, web, crypto, rev, misc, osint, malware) installed during environment setup

## This Repo

### Methodology

| Skill | Description |
|---|---|
| [methodology](methodology/SKILL.md) | CTF workflow, triage, ctfgrep, flag-search techniques |

### Forensics

| Skill | Domain | Key Tools |
|---|---|---|
| [forensics/disk](categories/forensics/disk/SKILL.md) | Disk image analysis | TSK (mmls, fls, icat, fsstat), foremost, photorec, bulk_extractor |
| [forensics/file](categories/forensics/file/SKILL.md) | File analysis & steganography | exiftool, binwalk, zsteg, steghide, stegseek, olevba, oledump |
| [forensics/memory](categories/forensics/memory/SKILL.md) | Memory dump analysis | Volatility 3, mquire |
| [forensics/network](categories/forensics/network/SKILL.md) | Packet capture analysis | tshark, tcpflow, scapy, ngrep, chaosreader |

### Tools

| Skill | Domain | Key Tools |
|---|---|---|
| [apk-analysis](tools/apk-analysis/SKILL.md) | Android reverse engineering | jadx, apktool, IDA Pro |
| [ida](tools/ida/SKILL.md) | Static binary analysis | IDA Pro Domain API (idalib, headless mode) |
| [kernel-gef](tools/kernel-gef/SKILL.md) | Kernel debugging | GDB + GEF via MCP |
| [libdebug](tools/libdebug/SKILL.md) | Dynamic binary analysis | libdebug (ptrace-based scriptable debugging) |

## External (ljagiello/ctf-skills)

Installed to `~/.claude/skills/` by `environment/003_install-claude-code.sh`.

| Skill | Category |
|---|---|
| ctf-crypto | Cryptography (RSA, AES, ECC, lattices, PRNGs, stream ciphers) |
| ctf-pwn | Binary exploitation (stack, heap, ROP, kernel, format string) |
| ctf-reverse | Reverse engineering (ELF, PE, custom VMs, WASM, anti-analysis) |
| ctf-web | Web exploitation (SQLi, SSTI, JWT, OAuth, deserialization, Web3) |
| ctf-misc | Mixed challenges (sandbox escapes, encodings, privilege escalation) |
| ctf-osint | Open-source intelligence (geolocation, social media) |
| ctf-malware | Malware analysis (obfuscated scripts, C2, dynamic analysis) |
