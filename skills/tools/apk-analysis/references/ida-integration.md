# IDA Pro Integration Reference

This document describes how the `apk-analysis` skill hands off native library analysis to the `analyze-with-ida-domain-api` skill.

## When to Trigger IDA Analysis

Native library analysis via IDA Pro is warranted when:

1. The APK contains **custom/app-specific** `.so` files (not just framework libs like libflutter, libreact, etc.)
2. The `.so` file contains **JNI exports** (`Java_*` symbols) that map to `native` methods in the decompiled Java code — meaning critical logic lives in native code
3. **Interesting strings** were found in the binary (crypto keywords, hardcoded URLs, license checks, etc.)
4. The Java code loads native libraries for **security-sensitive operations** (authentication, encryption, license validation, root detection, anti-tampering)
5. The user **explicitly requests** deeper binary analysis

## Pre-IDA Checklist

Before handing off to the IDA skill, ensure you have gathered:

- [ ] The `.so` file path (prefer arm64-v8a architecture)
- [ ] The `file` command output (ELF type, architecture, linking)
- [ ] Exported symbols list from `readelf -Ws`
- [ ] JNI function mappings (Java_ symbols → Java class.method)
- [ ] Interesting strings from `strings`
- [ ] The corresponding Java `native` method declarations from jadx output
- [ ] User's specific analysis goals (what are they looking for?)

## Handoff Format

When invoking the `analyze-with-ida-domain-api` skill, provide this context:

```
Binary to analyze: /home/claude/apk-work/<filename>.so
Architecture: arm64-v8a (or armeabi-v7a, x86, x86_64)
Source app: <package name from manifest>

Key functions to investigate:
- <JNI function name> → maps to <Java class.method()>
- <other exported function>

Context from Java layer:
- <Brief description of how the native method is called>
- <What the return value is used for>

Analysis goals:
- <What the user wants to know>
```

## Correlating IDA Results Back

After IDA analysis completes, correlate findings back to the Java layer:

1. **JNI bridges**: Match decompiled native functions to their Java callers
2. **Crypto operations**: If native code does encryption, trace where keys come from (Java side? hardcoded? derived?)
3. **Anti-tampering**: If native code checks signatures or integrity, note what happens on failure
4. **Network calls**: Native HTTP/socket calls bypass Java-level network security config — flag these
5. **String obfuscation**: If strings are decrypted at runtime in native code, document the decoded values

## Fallback (No IDA Available)

If the `analyze-with-ida-domain-api` skill is not available, the following information can still be extracted with basic tools:

| Tool | What it reveals |
|---|---|
| `file` | Architecture, ELF type, linking |
| `readelf -Ws` | Exported/imported symbols, JNI interface |
| `readelf -d` | Shared library dependencies |
| `strings` | Hardcoded strings, URLs, error messages |
| `objdump -d` (limited) | Raw disassembly (hard to read without IDA's analysis) |
| `nm -D` | Dynamic symbol table |

Report these findings clearly and suggest the user use IDA Pro or Ghidra locally for full analysis.
