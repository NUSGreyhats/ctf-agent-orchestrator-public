# Skills

Skills come from two sources:

1. **This repo** — methodology, forensics, and tool-specific skills
2. **[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)** — category skills (pwn, web, crypto, rev, misc, osint, malware, AI/ML) copied into the runtime skill catalog during install-script setup

## This Repo

The repository groups skills by source domain for maintainability. During
install-script setup, `install_scripts/013_install-skills.sh` copies each directory
that contains a `SKILL.md` into `all-skills/` as a top-level skill directory
named from its frontmatter `name:` field. The web app symlinks selected skills
from `all-skills/` into each challenge run's `.claude/skills` and
`.codex/skills` directories.

### Methodology

| Skill | Description |
|---|---|
| [ctf-methodology](methodology/SKILL.md) | CTF workflow, triage, ctfgrep, flag-search techniques |

### Forensics

| Skill | Domain | Key Tools |
|---|---|---|
| [disk-forensics](forensics/disk/SKILL.md) | Disk image analysis | TSK (mmls, fls, icat, fsstat), foremost, photorec, bulk_extractor |
| [file-forensics](forensics/file/SKILL.md) | File analysis & steganography | exiftool, binwalk, zsteg, steghide, stegseek, olevba, oledump |
| [memory-forensics](forensics/memory/SKILL.md) | Memory dump analysis | Volatility 3, mquire |
| [network-forensics](forensics/network/SKILL.md) | Packet capture analysis | tshark, tcpflow, scapy, ngrep, chaosreader |

### Tools

| Skill | Domain | Key Tools |
|---|---|---|
| [apk-analysis](tools/apk-analysis/SKILL.md) | Android reverse engineering | jadx, apktool, IDA Pro |
| [analyze-with-ida-domain-api](tools/ida/SKILL.md) | Static binary analysis | IDA Pro Domain API (idalib, headless mode) |
| [kernel-gef-debugging](tools/kernel-gef/SKILL.md) | Kernel debugging | GDB + GEF via MCP |
| [libdebug-debugging](tools/libdebug/SKILL.md) | Dynamic binary analysis | libdebug (ptrace-based scriptable debugging) |

## External (ljagiello/ctf-skills)

Copied to `all-skills/` by `install_scripts/013_install-skills.sh`.

| Skill | Category |
|---|---|
| ctf-crypto | Cryptography (RSA, AES, ECC, lattices, PRNGs, stream ciphers) |
| ctf-pwn | Binary exploitation (stack, heap, ROP, kernel, format string) |
| ctf-reverse | Reverse engineering (ELF, PE, custom VMs, WASM, anti-analysis) |
| ctf-web | Web exploitation (SQLi, SSTI, JWT, OAuth, deserialization, Web3) |
| ctf-misc | Mixed challenges (sandbox escapes, encodings, privilege escalation) |
| ctf-osint | Open-source intelligence (geolocation, social media) |
| ctf-malware | Malware analysis (obfuscated scripts, C2, dynamic analysis) |
| ctf-ai-ml | AI/ML challenges (model attacks, adversarial examples, LLM attacks) |
