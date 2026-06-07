---
name: apk-analysis
description: >
  Use for Android APK reverse engineering where the workflow specifically
  requires apktool (manifest, smali, resources, repackaging), jadx (DEX →
  Java/Kotlin decompilation with deobfuscation), or IDA Pro on bundled
  native .so libraries. The trip-ups this skill closes: deciding when JNI
  native libs hold the real logic vs. Java, the apktool→jadx sequencing,
  Java↔native function-name mapping (`Java_com_pkg_Class_method`), and
  packer/wrapper detection (Cordova, React Native, DexGuard). Skip for
  trivial APKs where `strings classes.dex | grep flag\{` solves it, for
  webview-only apps where the answer is a hardcoded URL, and for split
  APKs / .xapk / .aab bundles (use bundletool first).
---

# APK Analysis

Tool-specific recipes for `.apk` reversing. **Always run `unzip -p file.apk classes.dex | strings | grep -aE 'flag\{'` first** — many CTF APKs are solvable in one line.

```bash
mkdir -p /home/claude/apk-work
APK="<path-to-apk>"
```

## Triage with apktool (decide if native code matters)

apktool decodes resources/smali/manifest without full decompilation — fastest way to find out where the logic lives:

```bash
apktool d -f -o /home/claude/apk-work/apktool-output "$APK"
cat /home/claude/apk-work/apktool-output/AndroidManifest.xml

# This is the critical decision: does the APK ship native code?
find /home/claude/apk-work/apktool-output/lib -name "*.so" 2>/dev/null
```

**If `lib/` contains a `.so` that isn't a known framework** (libflutter, libreact-native, libunity, libfb, libgnustl, libcrypto, libssl, libsqlcipher) → the flag check is likely in native code; jump to **Native libraries** below.

Wrapper-app red flags (real logic is not in DEX):

| If you see... | Real logic is in... |
|---|---|
| `assets/index.android.bundle` | React Native — bundle the JS, not Java |
| `assets/www/` with `cordova.js` | Cordova — HTML/JS in `assets/www` |
| `assets/flutter_assets/` + `libapp.so` | Flutter — `libapp.so` (use `reFlutter` or Flutter snapshot dumper) |
| `lib/.../libcocos2dlua.so`, `libcocos2djs.so` | Cocos2d — Lua/JS asset bundle |
| Class names like `com.qihoo.util`, `com.bangcle`, `com.ijiami` | Packer — DEX is a stub loader |

## Java/Kotlin source review with jadx

```bash
jadx --deobf -d /home/claude/apk-work/jadx-output "$APK"
# For large APKs: --threads-count 4 --show-bad-code
```

`--show-bad-code` is the trip-up: methods that fail clean decompilation get omitted by default — obfuscators exploit this. Always include it on stubborn APKs.

The native-method declarations are the most useful jadx find for native-heavy APKs:

```bash
grep -rn --include="*.java" "native " /home/claude/apk-work/jadx-output/sources/
```

Each `native <type> methodName(...)` declaration corresponds to a `Java_com_pkg_Class_methodName` symbol in some `.so` — that's the reversing target.

## Native libraries (.so)

Pick `arm64-v8a` if present (modern), fall back to `armeabi-v7a` (older devices), then `x86_64`/`x86`:

```bash
LIB=$(find /home/claude/apk-work/apktool-output/lib/arm64-v8a -name '*.so' | head -1)
file "$LIB"

# JNI exports — these map back to Java native methods
readelf -Ws "$LIB" | grep ' Java_' | head -40

# Quick-win strings inside the lib
strings "$LIB" | grep -iE '(flag\{|http|key|secret|password|encrypt|decrypt|verify|sign|license|cert)'
```

The JNI naming convention (the trip-up):

```
Java_com_example_app_Crypto_check
↕
package com.example.app; class Crypto { native boolean check(String s); }
```

Underscores in package/class/method names are encoded as `_1` (e.g., `my_method` → `Java_..._my_1method`).

For full disassembly, hand off to IDA Pro via the `analyze-with-ida-domain-api`
skill. If that skill is unavailable, report the `readelf`/`strings` findings
and tell the user that deeper native analysis needs IDA or Ghidra.

## Resources / asset hunt (only if native + Java review came up empty)

```bash
# Hardcoded strings in resources (fast; misses encrypted ones)
cat /home/claude/apk-work/apktool-output/res/values/strings.xml | grep -iE '(flag|secret|key|api)'

# Anything in raw/assets — sometimes a flag literally lives in a JSON config
ls /home/claude/apk-work/apktool-output/assets/ /home/claude/apk-work/apktool-output/res/raw/ 2>/dev/null
```

## Common stuck states

- **Heavily obfuscated (every class is `a.a.a.a`)** — read `AndroidManifest.xml` to find real component names (Activities, Services, Receivers); those are anchors. Search jadx output for the fully-qualified names from the manifest.
- **Packed APK** — DEX is a stub. Static analysis won't reach the real code; you need a Frida/Objection runtime hook, or to dump the unpacked DEX from memory of a running instance.
- **Split APK / `.xapk` / `.aab`** — extract first: `bundletool build-apks --bundle=app.aab --output=out.apks` then unzip `out.apks` and analyze `base.apk`.
- **`.so` is stripped** — JNI exports survive (they have to, for the linker). Function-by-function, work backwards from the exported `Java_*` symbols.
