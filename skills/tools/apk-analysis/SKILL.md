---
name: apk-analysis
description: >
  Analyze Android APK files using reverse engineering tools (jadx, apktool, and optionally IDA Pro for native libraries).
  Use this skill whenever the user uploads or references an .apk file and wants to understand what it does,
  inspect its code, review permissions, examine the manifest, extract resources, look for hardcoded secrets,
  analyze native shared libraries (.so files), or perform any kind of Android app reverse engineering.
  Also trigger when the user says things like "reverse engineer this app", "decompile this APK",
  "what does this Android app do", "check this APK for malware", "analyze the native code in this app",
  or any mention of jadx, apktool, smali, dex, or Android app analysis.
---

# APK Analysis Skill

This skill guides you through comprehensive analysis of Android APK files using three core tools, each serving a distinct purpose. Always run the setup script first, then choose the analysis path based on what the user needs.

## Quick Reference — When to Use Each Tool

| Tool | Best For |
|---|---|
| **apktool** | Manifest, resources, smali, repackaging |
| **jadx** | Java/Kotlin source review, string search, control flow |
| **IDA Pro** | Native .so library reverse engineering (ARM/x86) |

## Step 1: Initial Triage with apktool

Always start here. apktool decodes the APK into a human-readable structure without full decompilation, giving you the fastest overview.

```bash
mkdir -p /home/claude/apk-work
apktool d -f -o /home/claude/apk-work/apktool-output "<path-to-apk>"
```

After decoding, perform these checks in order:

### 1a. AndroidManifest.xml

Read and analyze the decoded manifest:

```bash
cat /home/claude/apk-work/apktool-output/AndroidManifest.xml
```

### 1b. Resource Overview

Quickly scan for interesting resources:

```bash
# Check for raw or asset files (configs, certs, databases)
ls /home/claude/apk-work/apktool-output/assets/ 2>/dev/null
ls /home/claude/apk-work/apktool-output/res/raw/ 2>/dev/null

# Look for interesting file types
find /home/claude/apk-work/apktool-output \( -name "*.json" -o -name "*.xml" -o -name "*.db" -o -name "*.sqlite" -o -name "*.pem" -o -name "*.key" -o -name "*.cert" -o -name "*.p12" \) 2>/dev/null
```

### 1c. Native Libraries Check

This is critical — it determines whether IDA Pro analysis is warranted.

```bash
find /home/claude/apk-work/apktool-output/lib -name "*.so" 2>/dev/null | head -40
```

If `.so` files are found, catalog them:
- Note the architectures present (arm64-v8a, armeabi-v7a, x86, x86_64)
- Identify which are third-party/standard (e.g., `libflutter.so`, `libreact*.so`, `libunity.so`) vs. custom/app-specific
- Flag any with interesting names (crypto, license, native-lib, jni, security, etc.)
- Inform the user that deeper native analysis is available via IDA Pro (see Step 3)

## Step 2: Source Code Analysis with jadx

jadx decompiles DEX bytecode back to readable Java/Kotlin. This is where you'll spend most of your analysis time.

```bash
jadx --deobf -d /home/claude/apk-work/jadx-output "<path-to-apk>"
```

Key flags:
- `--deobf` : Renames obfuscated classes/methods to readable names
- `-d` : Output directory
- For large/complex APKs, add `--threads-count 4` for speed and `--show-bad-code` to include methods that failed to decompile cleanly (useful for seeing what the obfuscator is hiding)

### 2a. Project Structure Overview

```bash
# Get the package structure
find /home/claude/apk-work/jadx-output -name "*.java" | head -60
```

Map out the high-level architecture — identify packages for networking, crypto, storage, authentication, UI, etc.

### 2b. Secrets & Credential Hunting

Search for hardcoded sensitive data. This is one of the highest-value checks:

```bash
# API keys, tokens, secrets
grep -rn --include="*.java" -iE "(api[_-]?key|api[_-]?secret|token|password|secret[_-]?key|access[_-]?key|auth)" \
  /home/claude/apk-work/jadx-output/sources/ | grep -v "^Binary" | head -40

# URLs and endpoints
grep -rn --include="*.java" -E "https?://[^\s\"']+" \
  /home/claude/apk-work/jadx-output/sources/ | head -40

# Firebase / cloud config
grep -rn --include="*.java" -iE "(firebase|\.firebaseio\.com|googleapis\.com|amazonaws\.com)" \
  /home/claude/apk-work/jadx-output/sources/ | head -30

# Hardcoded IPs
grep -rn --include="*.java" -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
  /home/claude/apk-work/jadx-output/sources/ | head -20
```

Also check resource files from apktool output:
```bash
grep -rn -iE "(api[_-]?key|secret|password|token)" \
  /home/claude/apk-work/apktool-output/res/values/strings.xml 2>/dev/null
```

### 2c. Network & Communication Analysis

```bash
# HTTP clients and network calls
grep -rn --include="*.java" -iE \
  "(OkHttp|Retrofit|HttpURLConnection|Volley|WebSocket|\.connect\(|\.openConnection)" \
  /home/claude/apk-work/jadx-output/sources/ | head -30

# SSL/TLS pinning implementations
grep -rn --include="*.java" -iE "(CertificatePinner|ssl|TrustManager|X509|pinning|\.pin\()" \
  /home/claude/apk-work/jadx-output/sources/ | head -20

# Network security config
cat /home/claude/apk-work/apktool-output/res/xml/network_security_config.xml 2>/dev/null
```

### 2d. Crypto & Data Storage

```bash
# Encryption usage
grep -rn --include="*.java" -iE \
  "(Cipher|SecretKey|AES|RSA|DES|encrypt|decrypt|MessageDigest|SHA|MD5|PBKDF)" \
  /home/claude/apk-work/jadx-output/sources/ | head -30

# SharedPreferences (often stores sensitive data insecurely)
grep -rn --include="*.java" -iE "(SharedPreferences|getSharedPreferences|\.edit\(\)\.put)" \
  /home/claude/apk-work/jadx-output/sources/ | head -20

# SQLite / database usage
grep -rn --include="*.java" -iE "(SQLiteDatabase|SQLiteOpenHelper|Room|\.execSQL|\.rawQuery)" \
  /home/claude/apk-work/jadx-output/sources/ | head -20
```

### 2e. Deeper Code Review

Once you've identified interesting classes from the searches above, read them in full:

```bash
cat /home/claude/apk-work/jadx-output/sources/com/example/interesting/ClassName.java
```

When reviewing code, pay attention to:
- Authentication flows — how tokens are stored and transmitted
- Root/emulator detection — indicates the app has something to protect
- Dynamic code loading — `DexClassLoader`, `PathClassLoader`, `loadLibrary` calls
- Reflection — `Class.forName`, `getMethod`, `invoke` — often used to hide behavior
- Content providers with weak permissions
- WebView configurations — `setJavaScriptEnabled(true)` with `addJavascriptInterface` is a classic vulnerability
- Intent handling — can exported components be abused?

## Step 3: Native Library Analysis with IDA Pro

**Only proceed here if Step 1c identified interesting .so files AND the user wants deeper native analysis.**

Use the `ida` MCP tools for native library analysis. The general workflow is:

1. Extract the target .so file(s) from the APK:
   ```bash
   # Prefer arm64-v8a, fall back to armeabi-v7a
   cp /home/claude/apk-work/apktool-output/lib/arm64-v8a/<target>.so /home/claude/apk-work/
   ```

2. Before invoking IDA, do a preliminary check with basic CLI tools:
   ```bash
   # Basic binary info
   file /home/claude/apk-work/<target>.so

   # Exported symbols — often reveals the JNI interface
   readelf -Ws /home/claude/apk-work/<target>.so | grep -i "FUNC.*GLOBAL" | head -40

   # Interesting strings
   strings /home/claude/apk-work/<target>.so | grep -iE \
     "(http|key|secret|password|encrypt|decrypt|license|verify|sign|auth|cert)" | head -30

   # JNI function naming convention
   readelf -Ws /home/claude/apk-work/<target>.so | grep "Java_" | head -20
   ```

3. Correlate JNI functions back to the Java layer:
   - `Java_com_example_app_ClassName_methodName` maps to `com.example.app.ClassName.methodName()` in Java
   - Check the jadx output for `native` method declarations that match

4. Use the `ida` MCP tools for full disassembly and decompilation. Call `ida_open_idb` on the .so file, then use `ida_list_functions`, `ida_decompile`, and `ida_disasm_by_name` to analyze the native code.

5. If the `ida` MCP tools are **not available**, report your `readelf` and `strings` findings to the user and let them know full binary analysis would require IDA Pro or Ghidra, which aren't currently configured.

## Step 4: Produce the Report

After completing the relevant analysis steps, compile a report and present it to the user.

Use this structure (adapt sections based on what was actually analyzed):

```
# APK Analysis Report: [App Name / Package Name]

## Overview
- Package: ...
- Version: ...
- Min SDK: ... / Target SDK: ...
- File size: ...

## Permissions Analysis
[List permissions with risk assessment]

## Component Analysis
[Exported components, attack surface]

## Source Code Findings
### Hardcoded Secrets
### Network Configuration
### Cryptographic Implementation
### Data Storage
### Notable Code Patterns

## Native Libraries
[If applicable — list libraries, architecture, key findings from readelf/strings/IDA]

## Security Concerns
[Prioritized list of issues found, from most to least critical]

## Vulnerabilities
[What the vulnerabilities are, what severity/CVSS and how to trigger them]
```

## Handling Common Scenarios

**Obfuscated APKs**: If jadx output is heavily obfuscated (single-letter class names everywhere), use `--deobf` and focus on string searches, network calls, and entry points rather than reading obfuscated logic linearly. The `AndroidManifest.xml` always contains real component names — use those as anchors.

**Multi-DEX APKs**: jadx handles these automatically. apktool will show multiple `.dex` files in the output root — this is normal for large apps.

**Split APKs / App Bundles**: If the user provides a `.xapk`, `.apks`, or `.aab` file, inform them this skill expects a single `.apk`. Suggest using `bundletool` to convert, or analyze the base APK separately.

**Very Large APKs (>100MB)**: jadx may be slow or run out of memory. Use `--threads-count 2` and consider analyzing specific packages instead of the whole app.

**Packed/Protected APKs**: If you see packers (Qihoo 360, Bangcle, Ijiami, DexGuard, etc.) in the manifest or lib directory, note this to the user. The decompiled code will likely be a stub loader — the real code is decrypted at runtime. Surface-level analysis is still possible (permissions, manifest, resources, native libs) but source review will be limited.
