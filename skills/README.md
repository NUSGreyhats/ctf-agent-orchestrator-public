# Skills

Structured workflows that guide AI agents through CTF challenges. Skills are organized into three groups:

- **methodology/** — The entrypoint skill, read first for every challenge
- **categories/** — CTF challenge categories (crypto, forensics, pwn, rev, web, misc)
- **tools/** — Tool-specific skills referenced by category skills when needed

## Methodology

| Skill | Description |
|---|---|
| [methodology](methodology/SKILL.md) | CTF workflow, triage, ctfgrep, flag-search techniques |

## Categories

| Skill | Domain | Key Tools |
|---|---|---|
| [crypto](categories/crypto/SKILL.md) | Cryptography | RSA, AES, lattices, PRNGs, ECC, Z3, SageMath |
| [forensics/disk](categories/forensics/disk/SKILL.md) | Disk image analysis | TSK (mmls, fls, icat, fsstat), foremost, photorec, bulk_extractor |
| [forensics/file](categories/forensics/file/SKILL.md) | File analysis & steganography | exiftool, binwalk, zsteg, steghide, stegseek, olevba, oledump |
| [forensics/memory](categories/forensics/memory/SKILL.md) | Memory dump analysis | Volatility 3, mquire |
| [forensics/network](categories/forensics/network/SKILL.md) | Packet capture analysis | tshark, tcpflow, scapy, ngrep, chaosreader |
| [misc](categories/misc/SKILL.md) | Mixed/ambiguous challenges | Encoding checks, OSINT, layered artifacts |
| [pwn](categories/pwn/SKILL.md) | Binary exploitation | ROP, heap, shellcode, seccomp, format strings |
| [rev](categories/rev/SKILL.md) | Reverse engineering | IDA, custom VMs, anti-debugging, bytecode |
| [web](categories/web/SKILL.md) | Web exploitation | SQLi, SSTI, SSRF, path traversal, auth bypass |

## Tools

| Skill | Domain | Key Tools |
|---|---|---|
| [apk-analysis](tools/apk-analysis/SKILL.md) | Android reverse engineering | jadx, apktool, IDA Pro |
| [ida](tools/ida/SKILL.md) | Static binary analysis | IDA Pro Domain API (idalib, headless mode) |
| [kernel-gef](tools/kernel-gef/SKILL.md) | Kernel debugging | GDB + GEF via MCP |
| [libdebug](tools/libdebug/SKILL.md) | Dynamic binary analysis | libdebug (ptrace-based scriptable debugging) |
