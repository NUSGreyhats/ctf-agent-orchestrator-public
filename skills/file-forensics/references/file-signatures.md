# Extended File Signatures Reference

Use this reference when the file signature table in SKILL.md doesn't cover
the format you're dealing with.

## Image Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 8-byte signature |
| JPEG | `FF D8 FF E0` (JFIF) or `FF D8 FF E1` (EXIF) | Ends with `FF D9` |
| GIF87a | `47 49 46 38 37 61` | |
| GIF89a | `47 49 46 38 39 61` | Supports animation |
| BMP | `42 4D` | Size at offset 2 (LE u32) |
| TIFF (LE) | `49 49 2A 00` | Little-endian |
| TIFF (BE) | `4D 4D 00 2A` | Big-endian |
| WebP | `52 49 46 46 xx xx xx xx 57 45 42 50` | RIFF container |
| ICO | `00 00 01 00` | |
| PSD | `38 42 50 53` | Photoshop |
| SVG | `3C 73 76 67` or `3C 3F 78 6D 6C` | XML-based (`<svg` or `<?xml`) |

## PNG Chunk Structure

After the 8-byte signature, PNG files consist of chunks:

```
[4 bytes: length][4 bytes: type][N bytes: data][4 bytes: CRC]
```

Critical chunks:
- **IHDR** (must be first): width, height, bit depth, color type
- **IDAT**: compressed image data
- **IEND**: marks end of file (empty data)

Common corruption: wrong IHDR dimensions. Fix by editing width/height
at offsets 16-19 (width) and 20-23 (height) as big-endian u32.

## Archive Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| ZIP | `50 4B 03 04` | Local file header |
| ZIP (empty) | `50 4B 05 06` | End of central directory only |
| ZIP (spanned) | `50 4B 07 08` | |
| RAR4 | `52 61 72 21 1A 07 00` | |
| RAR5 | `52 61 72 21 1A 07 01 00` | |
| 7z | `37 7A BC AF 27 1C` | |
| GZIP | `1F 8B` | |
| BZIP2 | `42 5A 68` | `BZh` |
| XZ | `FD 37 7A 58 5A 00` | |
| ZSTD | `28 B5 2F FD` | |
| TAR | `75 73 74 61 72` at offset 257 | `ustar` |
| CAB | `4D 53 43 46` | Microsoft Cabinet |

## Document Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| PDF | `25 50 44 46 2D` | `%PDF-` |
| OLE2 (DOC/XLS/PPT) | `D0 CF 11 E0 A1 B1 1A E1` | Compound file |
| OOXML (DOCX/XLSX) | `50 4B 03 04` | ZIP with specific structure |
| RTF | `7B 5C 72 74 66` | `{\rtf` |
| XML | `3C 3F 78 6D 6C` | `<?xml` |

## Executable Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| ELF | `7F 45 4C 46` | Linux/Unix executable |
| PE/MZ | `4D 5A` | Windows executable |
| Mach-O (32) | `FE ED FA CE` | macOS |
| Mach-O (64) | `FE ED FA CF` | macOS 64-bit |
| Mach-O (universal) | `CA FE BA BE` | Fat binary |
| DEX | `64 65 78 0A` | Android Dalvik |
| Java class | `CA FE BA BE` | Same as Mach-O universal |
| WASM | `00 61 73 6D` | WebAssembly |

## Audio/Video Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| WAV | `52 49 46 46 xx xx xx xx 57 41 56 45` | RIFF/WAVE |
| MP3 (ID3v2) | `49 44 33` | |
| MP3 (frame) | `FF FB` or `FF F3` or `FF F2` | |
| FLAC | `66 4C 61 43` | |
| OGG | `4F 67 67 53` | |
| MIDI | `4D 54 68 64` | |
| AVI | `52 49 46 46 xx xx xx xx 41 56 49 20` | RIFF/AVI |
| MP4/MOV | `xx xx xx xx 66 74 79 70` | ftyp box at offset 4 |
| MKV/WebM | `1A 45 DF A3` | EBML header |
| FLV | `46 4C 56` | Flash Video |

## Database / Data Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | 16-byte sig |
| PCAP | `D4 C3 B2 A1` (LE) or `A1 B2 C3 D4` (BE) | |
| PCAPNG | `0A 0D 0D 0A` | Section header block |

## Crypto / Key Formats

| Format | Magic Bytes (hex/text) | Notes |
|--------|------------------------|-------|
| PEM | `2D 2D 2D 2D 2D 42 45 47 49 4E` | `-----BEGIN` |
| DER cert | `30 82` | ASN.1 sequence |
| PGP public | `99` or `98` | Old/new format |
| PGP message | `A8` or `C0-C3` | |
| SSH key | `73 73 68 2D` | `ssh-` (text) |
| GPG symmetric | `8C` | |
| KeePass | `03 D9 A2 9A` | KDBX |

## Disk / Filesystem Formats

| Format | Magic Bytes (hex) | Notes |
|--------|-------------------|-------|
| VMDK | `4B 44 4D 56` or `23 20 44 69 73 6B` | `KDMV` or `# Disk` |
| VDI | `3C 3C 3C 20` | Oracle VirtualBox |
| QCOW2 | `51 46 49 FB` | QEMU |
| ISO 9660 | `43 44 30 30 31` at offset 32769 | `CD001` |
| FAT/NTFS | `EB` at offset 0 | Jump instruction |
