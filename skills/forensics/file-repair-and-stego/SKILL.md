---
name: file-repair-and-stego
description: >
  Use when a single file falls into one of three trip-up cases the model
  reliably gets wrong without a recipe:
  (1) Corrupted-header repair where magic bytes / IHDR / SOI / EOI / CRC /
  central-directory fields have been clobbered and need precise byte-level
  reconstruction (PNG height-restore, JPEG marker repair, ZIP EOCD fixup);
  (2) Steganography extraction needing tool-specific invocations the model
  doesn't keep straight — zsteg (PNG/BMP only), steghide, stegseek with
  rockyou, outguess, openstego, LSB/bit-plane workflows;
  (3) Malicious office/PDF dissection via olevba, oledump, pcode2code,
  pdf-parser, peepdf where the macro/JS extraction sequence matters.
  Skip this skill when `exiftool` or `strings` already reveals the flag,
  when the file type doesn't match the recipe (e.g. zsteg on JPG), or for
  trivially-readable archives — try the cheap path first.
---

# File Repair and Steganography Extraction

Recipes for the three trip-up cases — header repair, stego extraction, malicious-doc dissection. **Always try `file`, `exiftool`, `strings | grep flag`, and `binwalk` first.** This skill is only worth the tokens once the cheap path has clearly failed or the file type matches a specific recipe below.

All artifacts go into `output/`.

## Header repair

Symptom: `file` reports "data" or wrong type for what should be PNG/JPEG/etc., or the application that owns the format refuses to open it.

```bash
hexdump -C -n 32 "$FILE"   # inspect current magic
```

### Magic bytes table

| Format | Magic (hex) |
|--------|-------------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` (must end `FF D9`) |
| GIF | `47 49 46 38 (37\|39) 61` |
| BMP | `42 4D` |
| TIFF | `49 49 2A 00` (LE) / `4D 4D 00 2A` (BE) |
| PDF | `25 50 44 46 2D` (`%PDF-`) — must end `%%EOF` |
| ZIP / OOXML | `50 4B 03 04` (central dir at end) |
| RAR | `52 61 72 21 1A 07` |
| 7z | `37 7A BC AF 27 1C` |
| GZIP | `1F 8B` |
| ELF | `7F 45 4C 46` |
| PE | `4D 5A` (`MZ`) |
| OLE/DOC/XLS | `D0 CF 11 E0 A1 B1 1A E1` |
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` |
| MP4/MOV | `xx xx xx xx 66 74 79 70` (`....ftyp` at offset 4) |
| WAV | `52 49 46 46 .. .. .. .. 57 41 56 45` |
| MP3 | `49 44 33` (`ID3`) |

### Patch

```bash
cp "$FILE" output/repaired
printf '\x89PNG\r\n\x1a\n' | dd of=output/repaired bs=1 count=8 conv=notrunc
file output/repaired
```

### Format-specific gotchas

**PNG** — IHDR chunk follows the magic at offset 8. Width/height (4 bytes each, big-endian) are at offsets 16 and 20. CTFs commonly zero out height to crop the visible image; restore it by computing height from filesize/width or by brute-forcing IHDR CRC. Use `pngcheck -v file.png` to confirm chunk integrity.

```python
# Brute-force PNG height by CRC of IHDR chunk
import struct, zlib
data = open("$FILE","rb").read()
ihdr = data[12:29]                 # 4 type + 13 data
width = struct.unpack(">I", ihdr[4:8])[0]
for h in range(1, 0x7fffffff):
    new = ihdr[:8] + struct.pack(">I", h) + ihdr[12:]
    if zlib.crc32(new) == struct.unpack(">I", data[29:33])[0]:
        print(f"width={width} height={h}")
        open("output/repaired.png","wb").write(data[:20]+struct.pack(">I",h)+data[24:])
        break
```

**JPEG** — must end `FF D9`. Verify: `tail -c 4 "$FILE" | xxd`. Truncated JPEGs often need just the trailer appended.

**ZIP** — End of central directory at end of file. If truncated, repair with `zip -FF broken.zip --out fixed.zip`. For ZIPs with corrupted local headers but intact central dir, `7z x` is more forgiving than `unzip`.

**PDF** — must end `%%EOF` and contain a valid xref table. `pdf-parser.py` recovers from many xref errors; `cpdf -decrypt input.pdf -o out.pdf` strips empty-password encryption.

## Metadata shortcuts

For archives, inspect metadata before extracting everything. Entry order,
CRC-32, sizes, comments, and timestamps can be the intended data:

```bash
unzip -Z -v "$FILE" | tee output/zip_verbose.txt
zipinfo -l "$FILE" | tee output/zip_listing.txt
```

For pickle or model files, inspect opcodes before loading untrusted code:

```bash
python3 -m pickletools "$FILE" | tee output/pickle_opcodes.txt
grep -E "GLOBAL|REDUCE|STACK_GLOBAL" output/pickle_opcodes.txt
```

For `.npy` arrays, check shape, dtype, and ranges before heavier side-channel
or ML analysis.

## Steganography

### zsteg (PNG/BMP only — wrong tool for JPG)

```bash
zsteg -a "$FILE" | tee output/zsteg.txt           # all bit orders/channels
zsteg -e "b1,rgb,lsb,xy" "$FILE" > output/payload.bin   # extract by descriptor
```

Descriptors come from zsteg output: `b<bits>,<channels>,<bit-order>,<scan-order>`.

### steghide / stegseek (JPEG/BMP/WAV/AU only)

Trip-up: steghide's success message goes to **stderr** — never use `2>/dev/null`.

```bash
# Try empty passphrase first (most common CTF case)
steghide extract -sf "$FILE" -p "" -xf output/steghide_out.bin 2>&1

# Bruteforce against rockyou (much faster than steghide brute)
stegseek "$FILE" -xf output/stegseek_out.bin 2>&1
stegseek "$FILE" /custom/wordlist.txt -xf output/stegseek_out.bin
```

### Audio spectrogram (WAV/MP3)

Hidden text in the frequency domain is invisible to `strings` but obvious in a spectrogram:

```bash
sox "$FILE" -n spectrogram -o output/spec.png
# inspect output/spec.png — look for text/QR codes/visual patterns
```

### Other techniques (when the above all fail)

- **Image diff** — if a "cover" original is published, XOR the two images byte-for-byte; LSB diffs reveal the payload.
- **Palette steg** (GIF/indexed PNG) — data encoded in palette index order; compare against a sorted palette.
- **EXIF thumbnail mismatch** — `exiftool -b -ThumbnailImage "$FILE" > thumb.jpg` and compare against the main image.
- **outguess** for JPEG (older challenges): `outguess -k "" -r "$FILE" output/outguess.bin`.
- **openstego** for BMP/PNG with a different LSB scheme than zsteg covers: `openstego extract -sf "$FILE" -p "" -xf output/openstego.bin`.

## Malicious Office / OLE2 documents

Trip-up: macro source can be removed leaving only compiled p-code (VBA stomping), and the extraction order matters — `olevba` first, fall through to `oledump` then `pcode2code`.

```bash
oleid "$FILE"                                # quick risk summary
olevba --deobf "$FILE" | tee output/olevba.txt   # extract + auto-deobfuscate macros
```

If `olevba` finds no source but `oleid` reports macros exist → VBA-stomped, recover from p-code:

```bash
pcode2code "$FILE" | tee output/pcode.txt
```

For raw stream access (modified macros, embedded objects):

```bash
oledump.py "$FILE"                           # list streams; M/m = macro
oledump.py -s <idx> -v "$FILE"               # decompress and dump VBA stream
oledump.py -s <idx> -d "$FILE" > output/stream_<idx>.bin   # raw bytes
```

For complex macros, emulate execution rather than reading obfuscated source:

```bash
docker run --rm -v "$(pwd):/work" cincan/vipermonkey vmonkey /work/"$(basename "$FILE")"
# Focus on the "Actions" section at the end of vmonkey output.
```

## PDF dissection

```bash
pdf-id.py "$FILE"                                   # tag summary
pdf-parser.py --search javascript "$FILE"           # find JS objects
pdf-parser.py --search /URI "$FILE"                 # find external URLs
pdf-parser.py --search /EmbeddedFile "$FILE"        # find attachments
pdf-parser.py --object <ID> --filter --raw \
  --dump output/stream_<ID>.bin "$FILE"             # extract+decompress a stream
cpdf -extract-text "$FILE"                          # plain text
cpdf -list-attached-files "$FILE"
```

For decoded JavaScript, look for `eval` of hex-encoded strings, `String.fromCharCode([...])` arrays, and base64 blobs decoded at runtime.

## After extraction

If carved files contain further embedded content, recurse: run `binwalk -e` on the extract, then re-apply this skill on each piece. ZIP-in-PNG-in-JPEG nesting is common in CTFs.
