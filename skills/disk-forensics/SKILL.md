---
name: disk-forensics
description: >
  Analyze disk images using The Sleuth Kit, foremost, bulk_extractor, and
  related tools. Use this skill whenever the user has a disk image (.raw, .dd,
  .img, .iso, .E01, .AFF, .vmdk, .vhd, .qcow2) and wants to analyze it —
  inspect partitions, list files, recover deleted files, carve data from
  unallocated space, extract artifacts, build timelines, or investigate
  filesystem state. Also trigger when the user mentions disk forensics, disk
  image analysis, sleuthkit, autopsy, "analyze this disk", "recover deleted
  files", "file carving", "what files are on this image", partition analysis,
  filesystem analysis, MFT parsing, inode inspection, timeline analysis,
  bulk_extractor, foremost, photorec, or any task involving disk image
  investigation. Trigger on any mention of TSK tools (mmls, fls, icat,
  fsstat, blkcat, img_stat, tsk_recover) or disk forensics techniques.
---

# Disk Forensics Skill

Analyze disk images to inspect partitions, explore filesystems, recover
deleted files, carve data, extract artifacts, and build timelines.

Primary tools: **The Sleuth Kit** (mmls, fsstat, fls, icat, blkcat,
img_stat, sigfind, sorter, tsk_recover), **foremost**, **bulk_extractor**,
**photorec**, **binwalk**, **strings**.

All analysis artifacts go into `output/` relative to the working directory.

## Step 1: Image Identification

Always start here. Understand the image before diving into specifics.

```bash
mkdir -p output
IMG="<path-to-disk-image>"
```

### 1a. File Type Detection

```bash
file "$IMG" | tee output/image_type.txt
```

Common results and what they mean:
- **DOS/MBR boot sector** — raw disk image with MBR partition table
- **GUID Partition Table** — raw disk image with GPT
- **EWF/Expert Witness** — E01 forensic format (use `ewfmount` first)
- **QEMU QCOW2** — QEMU image (convert with `qemu-img convert`)
- **ISO 9660** — optical disc image
- **data** — may be a raw partition image (no partition table)

### 1b. Image Metadata

```bash
img_stat "$IMG" | tee output/img_stat.txt
```

This reveals the image type TSK detects, sector size, and total size.

### 1c. Convert Non-Raw Formats

If the image is not raw, convert or mount it first:

```bash
# E01 → mount as raw
mkdir -p /tmp/ewf_mount
ewfmount "$IMG" /tmp/ewf_mount
IMG="/tmp/ewf_mount/ewf1"

# AFF → mount as raw
mkdir -p /tmp/aff_mount
affuse "$IMG" /tmp/aff_mount
IMG="/tmp/aff_mount/$(basename "$IMG").raw"

# VMDK / QCOW2 / VHD → convert to raw
qemu-img convert -f vmdk -O raw "$IMG" output/disk.raw
IMG="output/disk.raw"
```

After conversion, re-run `img_stat` on the new path.

## Step 2: Partition Analysis

### 2a. Partition Table

```bash
mmls "$IMG" | tee output/partitions.txt
```

mmls shows: slot, start sector, end sector, length, and description for
each partition. Note the **start offset** of each partition — this is
needed for all subsequent filesystem commands (`-o` flag).

If mmls reports no partition table, the image may be a single filesystem
(no partition table). Skip to **Step 3** with offset 0.

### 2b. Alternative Partition Views

```bash
fdisk -l "$IMG" 2>/dev/null | tee output/fdisk.txt
```

Cross-reference mmls and fdisk output to confirm partition layout.

### 2c. Identify Each Partition Type

For each partition found, note its type from mmls output:
- **NTFS / exFAT** — Windows
- **Linux (0x83)** — ext2/3/4, XFS, Btrfs
- **FAT12/16/32** — USB drives, SD cards, older systems
- **Swap (0x82)** — Linux swap (may contain memory fragments)
- **HFS+ / APFS** — macOS
- **Unallocated** — gaps between partitions (carve these)

## Step 3: Filesystem Analysis

Run these commands for each partition. Replace `OFFSET` with the start
sector from mmls output.

### 3a. Filesystem Details

```bash
OFFSET=<start_sector>
fsstat -o $OFFSET "$IMG" | tee output/fsstat_offset_${OFFSET}.txt
```

fsstat reveals: filesystem type, volume label, serial number, block/cluster
size, inode count, free space, and filesystem-specific metadata (superblock
for ext, MFT details for NTFS, FAT table info, etc.).

### 3b. Volume Label and Serial

Extract identifying information:

```bash
grep -iE "(volume name|volume serial|label|uuid|last mount)" \
  output/fsstat_offset_${OFFSET}.txt | tee output/volume_info.txt
```

## Step 4: File Listing and Directory Traversal

### 4a. Full File Listing

```bash
fls -r -p -o $OFFSET "$IMG" | tee output/fls_offset_${OFFSET}.txt
```

Flags: `-r` recursive, `-p` full path display. Each line shows:
- `r/r` — regular file (allocated)
- `d/d` — directory (allocated)
- `* r/r` — deleted file
- `* d/d` — deleted directory

### 4b. Filter Deleted Files

```bash
grep '^\*' output/fls_offset_${OFFSET}.txt \
  | tee output/deleted_files_offset_${OFFSET}.txt
```

### 4c. Filter by File Type

```bash
# Documents
grep -iE '\.(doc|docx|pdf|xls|xlsx|ppt|txt|csv|rtf)' \
  output/fls_offset_${OFFSET}.txt \
  | tee output/documents_offset_${OFFSET}.txt

# Images
grep -iE '\.(jpg|jpeg|png|gif|bmp|tiff|svg|ico)' \
  output/fls_offset_${OFFSET}.txt \
  | tee output/images_offset_${OFFSET}.txt

# Archives
grep -iE '\.(zip|rar|7z|tar|gz|bz2)' \
  output/fls_offset_${OFFSET}.txt \
  | tee output/archives_offset_${OFFSET}.txt

# Executables and scripts
grep -iE '\.(exe|dll|bat|ps1|sh|py|js|vbs|msi)' \
  output/fls_offset_${OFFSET}.txt \
  | tee output/executables_offset_${OFFSET}.txt

# Database and config files
grep -iE '\.(db|sqlite|sql|conf|cfg|ini|json|xml|yml|yaml|reg)' \
  output/fls_offset_${OFFSET}.txt \
  | tee output/configs_offset_${OFFSET}.txt
```

### 4d. List a Specific Directory

```bash
# List contents at a specific inode (get inode from fls output)
fls -o $OFFSET "$IMG" <inode>
```

## Step 5: File Extraction

### 5a. Extract by Inode

```bash
mkdir -p output/extracted
# Get the inode number from fls output (e.g., 12345)
icat -o $OFFSET "$IMG" <inode> > output/extracted/<filename>
file output/extracted/<filename>
```

### 5b. Extract Multiple Files by Type

Use `sorter` to categorize and extract files by type:

```bash
mkdir -p output/sorted
sorter -d output/sorted -o $OFFSET "$IMG" | tee output/sorter.txt
```

### 5c. Bulk Recovery of Deleted Files

```bash
mkdir -p output/recovered
tsk_recover -o $OFFSET -e "$IMG" output/recovered \
  | tee output/tsk_recover.txt
```

Flag `-e` recovers all files (allocated + deleted). Use without `-e` for
deleted files only.

### 5d. Extract Raw Data Units (Blocks/Clusters)

```bash
# Extract a specific block/cluster
blkcat -o $OFFSET "$IMG" <block_number> > output/block_<block_number>.bin

# Extract a range of blocks
blkcat -o $OFFSET "$IMG" <start_block> <num_blocks> \
  > output/blocks_<start_block>.bin
```

## Step 6: Timeline Analysis

Build a timeline of file activity (creation, modification, access, change).

### 6a. Generate Bodyfile

```bash
fls -r -m "/" -o $OFFSET "$IMG" > output/bodyfile_offset_${OFFSET}.txt
```

For multiple partitions, generate a bodyfile per partition then merge:

```bash
cat output/bodyfile_offset_*.txt > output/bodyfile_all.txt
```

### 6b. Convert to Timeline

```bash
mactime -b output/bodyfile_all.txt -d \
  > output/timeline.csv
```

The CSV contains: date, size, type (macb), permissions, uid, gid, inode,
and filename. `macb` indicates which timestamps changed:
- **m** — modified (content changed)
- **a** — accessed
- **c** — changed (metadata changed)
- **b** — born/created

### 6c. Filter Timeline by Date Range

```bash
mactime -b output/bodyfile_all.txt -d \
  <start_date> <end_date> \
  > output/timeline_filtered.csv
```

Date format: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`.

### 6d. Identify Activity Clusters

```bash
# Top 20 most active days
awk -F, '{print $1}' output/timeline.csv \
  | cut -d' ' -f1-3 | sort | uniq -c | sort -rn | head -20 \
  | tee output/active_days.txt
```

## Step 7: Unallocated Space and Slack Analysis

### 7a. Extract Unallocated Space

```bash
blkls -o $OFFSET "$IMG" > output/unallocated_offset_${OFFSET}.bin
```

### 7b. Strings from Unallocated Space

```bash
strings output/unallocated_offset_${OFFSET}.bin \
  > output/unalloc_strings.txt
strings -e l output/unallocated_offset_${OFFSET}.bin \
  > output/unalloc_strings_utf16.txt
```

Search for interesting patterns:

```bash
# Flags (CTF formats)
grep -iE '(flag\{|ctf\{|htb\{|pico\w*\{|key\{)' \
  output/unalloc_strings.txt \
  > output/unalloc_flags.txt 2>/dev/null || true

# URLs
grep -oE 'https?://[^\s"]+' output/unalloc_strings.txt \
  > output/unalloc_urls.txt 2>/dev/null || true

# Email addresses
grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' \
  output/unalloc_strings.txt \
  > output/unalloc_emails.txt 2>/dev/null || true

# Passwords, secrets
grep -iE '(password|passwd|secret|key|token|admin|login)' \
  output/unalloc_strings.txt \
  > output/unalloc_secrets.txt 2>/dev/null || true
```

### 7c. File Slack Space

File slack (space between end of file data and end of allocated
block/cluster) can contain remnants of previously deleted files:

```bash
# Extract slack space for a specific inode
blkcat -s -o $OFFSET "$IMG" <block_number> \
  > output/slack_block_<block_number>.bin
```

## Step 8: File Carving

Recover files from raw image data regardless of filesystem state.

### 8a. Foremost

```bash
mkdir -p output/foremost
foremost -i "$IMG" -o output/foremost -T 2>/dev/null
cat output/foremost/audit.txt 2>/dev/null | tee output/foremost_audit.txt
```

Foremost carves by file header/footer signatures. Review the audit file
for a summary of recovered files by type.

### 8b. PhotoRec

```bash
mkdir -p output/photorec
photorec /cmd "$IMG" fileopt,everything,enable,search \
  /d output/photorec /log 2>/dev/null
```

PhotoRec is especially good at recovering fragmented files and supports
more formats than foremost.

### 8c. Carve from Unallocated Space Only

To focus carving on deleted content, carve from the `blkls` output:

```bash
mkdir -p output/foremost_unalloc
foremost -i output/unallocated_offset_${OFFSET}.bin \
  -o output/foremost_unalloc -T 2>/dev/null
cat output/foremost_unalloc/audit.txt 2>/dev/null \
  | tee output/foremost_unalloc_audit.txt
```

### 8d. Binwalk (Embedded Structures)

```bash
binwalk "$IMG" | tee output/binwalk_scan.txt
```

Binwalk detects embedded filesystems, compressed archives, firmware
headers, and other structures. Extract with:

```bash
binwalk -e -C output/binwalk_extracted "$IMG"
```

## Step 9: Bulk Data Extraction

### 9a. bulk_extractor

Extract structured data (emails, URLs, credit cards, phone numbers,
domains, GPS coordinates, etc.) from the raw image without parsing the
filesystem:

```bash
mkdir -p output/bulk_extractor
bulk_extractor -o output/bulk_extractor "$IMG" 2>&1 \
  | tee output/bulk_extractor_log.txt
```

Key output files:
- `email.txt` — email addresses
- `url.txt` — URLs found in the image
- `domain.txt` — domain names
- `telephone.txt` — phone numbers
- `ccn.txt` — credit card numbers
- `ip.txt` — IP addresses
- `exif.txt` — EXIF metadata from embedded images
- `find.txt` — search term hits
- `zip.txt` — ZIP file components
- `rar.txt` — RAR file components
- `json.txt` — JSON fragments
- `kml.txt` — GPS coordinates in KML format

### 9b. Review Top Findings

```bash
for f in output/bulk_extractor/*.txt; do
  count=$(wc -l < "$f" 2>/dev/null || echo 0)
  [ "$count" -gt 0 ] && echo "$count $f"
done | sort -rn | head -20 | tee output/bulk_extractor_summary.txt
```

## Step 10: Keyword Searching

### 10a. Search Across Entire Image

```bash
# Search for a keyword in the raw image
strings "$IMG" | grep -i "<keyword>" \
  | tee output/keyword_<keyword>.txt

# Search with context (byte offset)
grep -obai "<keyword>" "$IMG" \
  | tee output/keyword_offsets_<keyword>.txt
```

### 10b. Search with sigfind

Find specific byte signatures in the image:

```bash
# Search for a hex signature (e.g., PK header for ZIP)
sigfind -o $OFFSET 504B0304 "$IMG" \
  | tee output/sigfind_zip.txt

# Search for JPEG headers
sigfind -o $OFFSET FFD8FF "$IMG" \
  | tee output/sigfind_jpeg.txt
```

### 10c. Locate and Extract by Offset

When a keyword or signature is found at a byte offset, calculate which
block and inode it belongs to:

```bash
# Get block size from fsstat
BLOCK_SIZE=$(grep -i "block size" output/fsstat_offset_${OFFSET}.txt \
  | head -1 | grep -oE '[0-9]+')

# Calculate block number from byte offset
BYTE_OFFSET=<offset_from_grep>
BLOCK_NUM=$(( (BYTE_OFFSET / BLOCK_SIZE) - OFFSET ))

# Find which file owns that block
ifind -o $OFFSET -d $BLOCK_NUM "$IMG"

# Then extract the file by inode
icat -o $OFFSET "$IMG" <inode> > output/extracted/found_file.bin
```

## Step 11: Mounting the Image

For interactive browsing or when TSK commands are insufficient.

### 11a. Mount a Single-Partition Image

```bash
mkdir -p /mnt/evidence
mount -o ro,loop,noexec,nosuid "$IMG" /mnt/evidence
```

### 11b. Mount a Specific Partition

Calculate the byte offset: `start_sector * sector_size`.

```bash
# Sector size is typically 512 bytes
BYTE_OFFSET=$(( OFFSET * 512 ))
mount -o ro,loop,offset=$BYTE_OFFSET,noexec,nosuid "$IMG" /mnt/evidence
```

### 11c. Mount with losetup + kpartx (Multi-Partition)

```bash
losetup -fP --read-only "$IMG"
LOOP=$(losetup -j "$IMG" | cut -d: -f1)
ls ${LOOP}p*

# Mount individual partitions
mkdir -p /mnt/evidence_p1
mount -o ro,noexec,nosuid ${LOOP}p1 /mnt/evidence_p1
```

Always mount read-only (`ro`) to preserve evidence integrity.

### 11d. Cleanup

```bash
umount /mnt/evidence* 2>/dev/null
losetup -d $LOOP 2>/dev/null
umount /tmp/ewf_mount 2>/dev/null
umount /tmp/aff_mount 2>/dev/null
```

## Step 12: Common Artifact Locations

After mounting or extracting files, check these OS-specific paths for
forensic artifacts.

### Windows

| Artifact | Path |
|----------|------|
| Registry hives | `Windows/System32/config/{SAM,SYSTEM,SOFTWARE,SECURITY}` |
| User registry | `Users/<user>/NTUSER.DAT` |
| Event logs | `Windows/System32/winevt/Logs/*.evtx` |
| Prefetch | `Windows/Prefetch/*.pf` |
| Recent files | `Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/` |
| Browser history (Chrome) | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/History` |
| Browser history (Firefox) | `Users/<user>/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite` |
| Downloads | `Users/<user>/Downloads/` |
| Recycle Bin | `$Recycle.Bin/<SID>/` |
| USB history | `Windows/inf/setupapi.dev.log` |
| Scheduled tasks | `Windows/System32/Tasks/` |
| PowerShell history | `Users/<user>/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` |
| Amcache | `Windows/AppCompat/Programs/Amcache.hve` |
| SRUM | `Windows/System32/sru/SRUDB.dat` |

### Linux

| Artifact | Path |
|----------|------|
| Auth logs | `/var/log/auth.log`, `/var/log/secure` |
| Syslog | `/var/log/syslog`, `/var/log/messages` |
| Bash history | `/home/<user>/.bash_history`, `/root/.bash_history` |
| Cron jobs | `/etc/crontab`, `/var/spool/cron/` |
| SSH keys | `/home/<user>/.ssh/` |
| User accounts | `/etc/passwd`, `/etc/shadow` |
| Installed packages | `/var/log/dpkg.log`, `/var/log/yum.log` |
| Systemd journals | `/var/log/journal/` |
| Apache/Nginx logs | `/var/log/apache2/`, `/var/log/nginx/` |
| Browser (Chrome) | `/home/<user>/.config/google-chrome/Default/History` |
| Browser (Firefox) | `/home/<user>/.mozilla/firefox/*/places.sqlite` |
| Last logins | `/var/log/wtmp`, `/var/log/btmp` |

### macOS

| Artifact | Path |
|----------|------|
| System log | `/var/log/system.log` |
| Unified logs | `/var/db/diagnostics/` |
| User plists | `/Users/<user>/Library/Preferences/` |
| Safari history | `/Users/<user>/Library/Safari/History.db` |
| Quarantine events | `/Users/<user>/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` |
| Spotlight metadata | `/.Spotlight-V100/` |
| FSEvents | `/.fseventsd/` |
| Keychain | `/Users/<user>/Library/Keychains/` |

### Artifact Extraction

For SQLite databases (browser history, etc.):

```bash
# Extract and query
icat -o $OFFSET "$IMG" <inode> > output/extracted/history.sqlite
sqlite3 output/extracted/history.sqlite \
  "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 50;" \
  | tee output/browser_history.txt
```

## Step 13: Targeted Investigation

After initial analysis, drill into findings based on what was discovered.

### Suspicious File Found

```bash
# Extract it
icat -o $OFFSET "$IMG" <inode> > output/extracted/suspicious_file
# Identify it
file output/extracted/suspicious_file
# Get metadata
istat -o $OFFSET "$IMG" <inode> | tee output/istat_<inode>.txt
# Check for alternate data streams (NTFS)
fls -o $OFFSET "$IMG" <inode>
```

`istat` shows: inode metadata, MAC timestamps, allocated blocks, and
file size. For NTFS, it also shows attributes and alternate data streams.

### Interesting Time Range

```bash
# Filter timeline to a specific window
mactime -b output/bodyfile_all.txt -d \
  "2024-01-15" "2024-01-16" \
  > output/timeline_jan15.csv
```

### Recover a Specific Deleted File

```bash
# Find it in the deleted files list
grep -i "<filename>" output/deleted_files_offset_${OFFSET}.txt
# Extract by inode (may be partial if blocks were reused)
icat -o $OFFSET "$IMG" <inode> > output/extracted/<filename>
file output/extracted/<filename>
```

### Hash Verification

```bash
# Hash all extracted files
find output/extracted -type f -exec sha256sum {} \; \
  | tee output/file_hashes.txt

# Hash the full disk image for evidence integrity
sha256sum "$IMG" | tee output/image_hash.txt
```

## Step 14: Synthesis and Reporting

After running relevant analysis steps, synthesize findings:

1. **Image overview** — format, size, sector size, partition layout
2. **Filesystem summary** — types, labels, total/free space per partition
3. **File inventory** — key files found, deleted files, interesting types
4. **Timeline highlights** — activity clusters, suspicious timestamps
5. **Recovered artifacts** — deleted files, carved files, extracted data
6. **Keyword hits** — flags, credentials, URLs, email addresses
7. **Unallocated findings** — data remnants, carved files from free space
8. **Artifact analysis** — browser history, logs, registry, config files
9. **Evidence integrity** — image hash for chain of custody

If extracted files need further analysis (documents, images, executables),
apply the **file-forensics** skill to each. If a memory dump is found
within the disk image, apply the **memory-forensics** skill.
