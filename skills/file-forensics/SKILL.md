---
name: file-forensics
description: >
  Analyze, recover, and extract data from files using forensics techniques
  and tools. Use this skill whenever the user has a file they want to inspect,
  repair, carve, or extract hidden data from — including corrupted files,
  images with steganography, malicious PDFs, suspicious Office documents (OLE),
  or any file where the goal is to recover or reveal hidden content.
  Also trigger when the user mentions file forensics, file carving, binwalk,
  steganography, zsteg, steghide, stegseek, exiftool, "fix this file",
  "recover data", "extract hidden data", "analyze this PDF", "check for
  macros", olevba, oledump, pcode2code, "what's embedded in this file",
  hex analysis, file signature repair, magic bytes, or any task involving
  forensic file analysis. Trigger on any file where the user suspects
  corruption, hidden payloads, embedded files, or steganographic content,
  even if they don't use the word "forensics".
---

# File Forensics Skill

Analyze files to identify, recover, repair, and extract data. This skill
covers corrupted file repair, steganography extraction, embedded file
carving, and malicious document analysis.

All analysis artifacts go into `output/` relative to the working directory.

## Step 1: Initial Triage

Always start here. Identify what you're working with before diving into
specialized analysis.

```bash
mkdir -p output
FILE="<path-to-file>"
```

### 1a. File Identification

```bash
file "$FILE" | tee output/file_type.txt
```

If `file` reports something unexpected (e.g., "data" for what should be a
PNG), this signals possible corruption or deliberate obfuscation — proceed
to **Step 2 (File Signature Repair)**.

### 1b. Metadata Extraction

```bash
exiftool "$FILE" | tee output/metadata.txt
```

Look for: author names, software used, GPS coordinates, timestamps,
comments, embedded thumbnails, suspicious fields. Metadata often contains
flags, hints, or attribution in CTF challenges.

### 1c. Strings Extraction

```bash
strings "$FILE" > output/strings.txt
strings -e l "$FILE" > output/strings_utf16.txt
```

Search for interesting patterns:

```bash
# URLs
grep -oE 'https?://[^\s"]+' output/strings.txt > output/urls.txt 2>/dev/null || true

# Flags (common CTF formats)
grep -iE '(flag\{|ctf\{|htb\{|pico\w*\{|key\{)' output/strings.txt > output/flags.txt 2>/dev/null || true

# Base64 candidates (20+ chars to reduce noise)
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' output/strings.txt > output/base64_candidates.txt 2>/dev/null || true

# Passwords, secrets
grep -iE '(password|secret|key|token|admin|login|credentials)' output/strings.txt > output/secrets.txt 2>/dev/null || true
```

If base64 candidates are found, try decoding them:

```bash
while IFS= read -r line; do
  echo "=== $line ===" >> output/base64_decoded.txt
  echo "$line" | base64 -d 2>/dev/null >> output/base64_decoded.txt
  echo "" >> output/base64_decoded.txt
done < output/base64_candidates.txt
```

### 1d. Embedded File Detection

```bash
binwalk "$FILE" | tee output/binwalk_scan.txt
```

If binwalk finds embedded files (ZIP archives, images, firmware headers,
certificates, etc.), extract them:

```bash
binwalk -e -C output/binwalk_extracted "$FILE"
```

After extraction, recursively analyze each carved file — it may itself
contain further embedded data or steganographic content.

### 1e. Hex Inspection

Inspect the first 256 bytes for magic bytes and structure:

```bash
hexdump -C -n 256 "$FILE" | tee output/hex_header.txt
```

For targeted inspection of specific offsets:

```bash
hexdump -C -s <offset> -n <length> "$FILE"
```

## Step 2: File Signature Repair

When `file` misidentifies a file, or the file fails to open in its expected
application, the magic bytes (first few bytes) may be corrupted.

### Common File Signatures

| Format | Magic Bytes (hex) | ASCII |
|--------|-------------------|-------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| JPEG | `FF D8 FF` | `...` |
| GIF87a | `47 49 46 38 37 61` | `GIF87a` |
| GIF89a | `47 49 46 38 39 61` | `GIF89a` |
| BMP | `42 4D` | `BM` |
| TIFF (LE) | `49 49 2A 00` | `II*.` |
| TIFF (BE) | `4D 4D 00 2A` | `MM.*` |
| PDF | `25 50 44 46 2D` | `%PDF-` |
| ZIP | `50 4B 03 04` | `PK..` |
| RAR | `52 61 72 21 1A 07` | `Rar!..` |
| 7z | `37 7A BC AF 27 1C` | `7z...` |
| GZIP | `1F 8B` | `..` |
| ELF | `7F 45 4C 46` | `.ELF` |
| PE/EXE | `4D 5A` | `MZ` |
| OLE/DOC | `D0 CF 11 E0 A1 B1 1A E1` | `........` |
| OOXML/DOCX | `50 4B 03 04` (ZIP) | `PK..` |
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | `SQLite format 3.` |
| WAV | `52 49 46 46 xx xx xx xx 57 41 56 45` | `RIFF....WAVE` |
| MP3 (ID3) | `49 44 33` | `ID3` |
| FLV | `46 4C 56` | `FLV` |
| MP4/MOV | `xx xx xx xx 66 74 79 70` | `....ftyp` |

### Repair Process

1. Inspect current header: `hexdump -C -n 16 "$FILE"`
2. Compare against expected signature from the table above
3. Infer the correct type from context clues: file extension, internal
   structure visible in hex, binwalk output, strings output
4. Patch the corrupted bytes:

```bash
cp "$FILE" output/repaired_file
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' | dd of=output/repaired_file bs=1 count=8 conv=notrunc
```

5. Verify the repair: `file output/repaired_file`

Beyond magic bytes, some formats have additional structural requirements:

- **PNG**: Requires valid IHDR chunk immediately after signature. Check chunk
  structure with `pngcheck` if available, or inspect hex at offset 8.
- **JPEG**: Must end with `FF D9`. Check with `hexdump -C "$FILE" | tail -5`.
- **ZIP**: Central directory at end of file. If missing, the archive is
  truncated — try `zip -FF` to fix.
- **PDF**: Check for `%%EOF` at the end and valid xref table.

## Step 3: Steganography Analysis

Apply these techniques when dealing with image or audio files, especially
when initial triage doesn't reveal the hidden data.

### 3a. PNG/BMP — LSB Analysis with zsteg

zsteg is the go-to tool for LSB (Least Significant Bit) steganography in
PNG and BMP files. It tests many bit-plane and channel combinations
automatically.

```bash
zsteg "$FILE" | tee output/zsteg_results.txt
```

For a more thorough scan:

```bash
# All bit orders and channel combinations
zsteg -a "$FILE" | tee output/zsteg_all.txt
```

To extract a specific payload once identified:

```bash
zsteg -e "<payload_descriptor>" "$FILE" > output/zsteg_extracted.bin
```

The payload descriptor comes from zsteg output (e.g., `b1,rgb,lsb,xy`).

### 3b. JPEG/BMP/WAV/AU — steghide / stegseek

steghide embeds data in JPEG, BMP, WAV, and AU files using a passphrase.
stegseek is a faster alternative that can also bruteforce the passphrase.

**Try extraction without a passphrase first.**
IMPORTANT: Never use `2>/dev/null` with steghide — its success message
("wrote extracted data to ...") prints to stderr and is the only way to
confirm extraction worked. Always use `2>&1` to capture it.

```bash
steghide extract -sf "$FILE" -p "" -xf output/steghide_extracted.bin 2>&1 | tee output/steghide_result.txt
```

**Bruteforce with stegseek** (uses rockyou.txt by default):

```bash
stegseek "$FILE" -xf output/stegseek_extracted.bin 2>&1 | tee output/stegseek_result.txt
```

With a custom wordlist:

```bash
stegseek "$FILE" /path/to/wordlist.txt -xf output/stegseek_extracted.bin
```

**If you have a known passphrase:**

```bash
steghide extract -sf "$FILE" -p "passphrase" -xf output/steghide_extracted.bin
```

### 3c. Additional Steg Techniques

If zsteg, steghide, and stegseek don't find anything, consider these
approaches:

- **Pixel value analysis**: Look at color channels individually.
  Use Python with PIL/Pillow to extract specific bit planes.
- **Image comparison**: If an original (cover) image is available,
  XOR or diff the two images to reveal the hidden data.
- **Palette-based steg**: For GIF/indexed-color PNGs, examine the
  color palette order — data can be encoded in palette indices.
- **Audio spectrogram**: For WAV/MP3 files, generate a spectrogram
  (e.g., with `sox` or `ffmpeg`) to check for visual messages
  hidden in the frequency domain.

```bash
# Spectrogram from audio file
sox "$FILE" -n spectrogram -o output/spectrogram.png 2>/dev/null
```

- **EXIF thumbnail mismatch**: Compare the EXIF thumbnail to the
  main image — they may differ if the image was edited after
  steganographic embedding.

```bash
exiftool -b -ThumbnailImage "$FILE" > output/exif_thumbnail.jpg 2>/dev/null
```

## Step 4: PDF Analysis

Use these tools when dealing with PDF files, especially ones suspected of
containing malicious payloads, JavaScript, embedded files, or obfuscated
content.

### 4a. PDF Overview with pdf-id.py

Get a high-level summary of PDF objects and potentially dangerous elements:

```bash
pdf-id.py "$FILE" | tee output/pdf_id.txt
```

Key indicators to watch for:
- **/JS, /JavaScript** — embedded JavaScript (common in exploits)
- **/OpenAction, /AA** — automatic actions on open
- **/ObjStm** — object streams (can hide malicious objects)
- **/URI** — external URL references
- **/EmbeddedFile** — files embedded within the PDF
- **/XFA** — XML Forms Architecture (can contain scripts)
- **/Launch** — launch external application
- **/RichMedia** — embedded Flash/multimedia
- **/Encrypt** — encryption (may impede analysis)

### 4b. Parse and Extract Objects with pdf-parser.py

Dig into specific PDF objects identified by pdf-id.py:

```bash
# List all objects with a summary
pdf-parser.py "$FILE" | tee output/pdf_parsed.txt

# Search for specific elements
pdf-parser.py --search javascript "$FILE" | tee output/pdf_javascript.txt
pdf-parser.py --search /URI "$FILE" | tee output/pdf_uris.txt
pdf-parser.py --search /EmbeddedFile "$FILE" | tee output/pdf_embedded.txt

# Extract a specific object by ID (get ID from previous output)
pdf-parser.py --object <ID> "$FILE" | tee output/pdf_object_<ID>.txt

# Extract and decompress a stream from an object
pdf-parser.py --object <ID> --filter --raw --dump output/pdf_stream_<ID>.bin "$FILE"
```

### 4c. PDF Manipulation with cpdf

cpdf is useful for extracting content, removing encryption, and
restructuring PDFs:

```bash
# Extract all text
cpdf -extract-text "$FILE" > output/pdf_text.txt 2>/dev/null

# List attachments
cpdf -list-attached-files "$FILE" 2>/dev/null | tee output/pdf_attachments.txt

# Extract attachments
mkdir -p output/pdf_attachments
cpdf -extract-attached-files "$FILE" -o output/pdf_attachments/ 2>/dev/null

# Remove encryption (if no password or empty password)
cpdf -decrypt "$FILE" -o output/pdf_decrypted.pdf 2>/dev/null

# Get page count and info
cpdf -info "$FILE" 2>/dev/null | tee output/pdf_info.txt

# Extract specific pages
cpdf "$FILE" 1-5 -o output/pdf_pages_1_5.pdf 2>/dev/null
```

### 4d. Deobfuscation

If JavaScript is found, look for common obfuscation patterns:

- **eval()** calls wrapping encoded strings
- **unescape()** with hex-encoded payloads
- **String.fromCharCode()** arrays
- **Base64-encoded** blobs decoded at runtime

Extract the JS code, then manually decode or use a JS beautifier. Look for
shellcode, URLs, or exploit payloads in the decoded output.

## Step 5: OLE Document Analysis

Use these tools for Microsoft Office documents (DOC, XLS, PPT) and other
OLE2 Compound files. These formats can contain VBA macros, embedded objects,
and other active content used in malware delivery.

### 5a. OLE Overview with oleid

Get a quick summary of an OLE file's features and risk indicators:

```bash
oleid "$FILE" | tee output/oleid_summary.txt
```

Key indicators:
- **VBA Macros** — embedded Visual Basic for Applications code
- **External Relationships** — links to external resources
- **Encrypted** — password-protected content
- **Flash objects** — embedded SWF (exploit vector)
- **ObjectPool** — embedded OLE objects

### 5b. Extract VBA Macros with olevba

Dump all macro source code and analyze for suspicious patterns:

```bash
olevba "$FILE" | tee output/olevba_output.txt

# Decode obfuscated strings
olevba --deobf "$FILE" | tee output/olevba_deobfuscated.txt
```

olevba flags suspicious keywords automatically. Watch for:
- **AutoOpen, Document_Open, Workbook_Open** — auto-execute macros
- **Shell, WScript.Shell, CreateObject** — command execution
- **PowerShell, cmd.exe** — spawning shells
- **URLDownloadToFile, XMLHTTP** — downloading payloads
- **Environ, Temp** — accessing filesystem paths
- **Base64, Chr, Asc** — string obfuscation
- **CallByName** — indirect function calls to evade detection

### 5c. Parse OLE Streams with oledump.py

Inspect the internal structure and extract individual streams:

```bash
# List all streams (streams with 'M' or 'm' contain macros)
oledump.py "$FILE" | tee output/oledump_streams.txt

# Dump a specific stream (by index from the listing)
oledump.py -s <stream_index> "$FILE" | tee output/oledump_stream_<stream_index>.txt

# Dump and decompress a VBA macro stream
oledump.py -s <stream_index> -v "$FILE" | tee output/oledump_vba_<stream_index>.txt

# Extract raw bytes from a stream
oledump.py -s <stream_index> -d "$FILE" > output/oledump_raw_<stream_index>.bin
```

### 5d. Decompile P-code with pcode2code

VBA macros can exist in two forms: source code and compiled p-code. Some
malware removes the source code and keeps only p-code to evade olevba.
pcode2code recovers the VBA source from compiled p-code.

```bash
pcode2code "$FILE" | tee output/pcode_decompiled.txt
```

Use this when olevba shows macros exist (oleid reports them) but olevba
can't extract readable source — the macro may be p-code only (aka
"VBA stomping" or "VBA purging").

### 5e. Emulate Macros with vmonkey

For complex or heavily obfuscated macros, emulate execution to see what
the macro actually does without running it on a real system:

```bash
docker run --rm -v "$(pwd):/work" cincan/vipermonkey \
  vmonkey /work/"$(basename "$FILE")" 2>&1 | tee output/vmonkey_emulation.txt
```

vmonkey traces variable assignments, function calls, and shell commands
that the macro would execute, revealing:
- Decoded URLs and C2 addresses
- Dropped file contents and paths
- Registry modifications
- PowerShell commands

If vmonkey emulation is noisy, focus on the "Actions" section at the
end of its output — it summarizes the observable behaviors.

## Step 6: Synthesis and Reporting

After running the relevant analysis steps, synthesize the findings:

1. **Summarize the file type and structure** — what is it, is it intact?
2. **List all extracted artifacts** — carved files, decoded strings,
   extracted macros, steganographic payloads
3. **Highlight suspicious or notable findings** — flags, hidden messages,
   malicious indicators, IOCs (IPs, URLs, hashes)
4. **Recommend next steps** — deeper analysis of extracted files,
   dynamic analysis in a sandbox, correlation with threat intel

If any extracted artifacts are themselves files (e.g., a ZIP carved from
binwalk, or an attachment from a PDF), recursively apply this skill to
analyze them.
