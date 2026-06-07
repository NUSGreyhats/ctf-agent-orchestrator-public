---
name: tsk-disk-recovery
description: >
  Use ONLY when the disk image is in a forensic format that needs specialized
  mounting (.E01/EWF via ewfmount, .qcow2/.vmdk/.vhd via qemu-img convert,
  .AFF via affuse) OR when the task explicitly requires Sleuth Kit-style
  filesystem inspection: deleted-file recovery via inode (icat / tsk_recover),
  MFT parsing, slack/unallocated-space carving with bulk_extractor or
  foremost, or partition-offset arithmetic via mmls→fls. Skip this skill
  for plain raw/.dd/.img images that mount cleanly with `mount -o loop`,
  for ZIP/TAR/docker archives misidentified as "images", and for cases
  where `strings img | grep -aE 'flag\{'` already reveals the flag — try
  the cheap path first.
---

# Disk Recovery via Sleuth Kit

Tool-specific recipes for forensic-format disk images and TSK-style filesystem inspection. **Always try `strings img | grep -aE 'flag\{'` and `mount -o loop` first** — the recipes below are only worth running when the cheap path has failed.

All artifacts go into `output/`.

```bash
mkdir -p output
IMG="<path-to-disk-image>"
file "$IMG"
```

## Convert non-raw formats

The trip-up: each forensic format has its own mount/convert command. `mount -o loop` does not work on E01/QCOW2/VMDK directly.

```bash
# E01 / EWF (Expert Witness Format)
mkdir -p /tmp/ewf_mount
ewfmount "$IMG" /tmp/ewf_mount
IMG="/tmp/ewf_mount/ewf1"

# AFF
mkdir -p /tmp/aff_mount
affuse "$IMG" /tmp/aff_mount
IMG="/tmp/aff_mount/$(basename "$IMG").raw"

# QCOW2 / VMDK / VHD → convert to raw
qemu-img convert -f qcow2 -O raw "$IMG" output/disk.raw   # -f matches source
IMG="output/disk.raw"
```

If `file` reports `ADSEGMENTEDFILE` or `ADLOGICALIMAGE`, treat it as an AD1
logical image. Extract the logical files with an AD1-capable parser/tool first;
raw-disk TSK workflows and partition offsets are usually the wrong path.

After conversion, `IMG` should point at a raw file.

## Partitions and offset arithmetic

The trip-up: every TSK command needs the partition start sector via `-o`. `fsstat`/`fls`/`icat` against the wrong offset returns garbage silently.

```bash
mmls "$IMG"            # lists slot, start sector, length, type
```

If mmls reports no partition table, the image is a single filesystem — use `OFFSET=0`. Otherwise pick the start sector of the target partition:

```bash
OFFSET=<start_sector>
fsstat -o $OFFSET "$IMG" | tee output/fsstat.txt
```

`fsstat` confirms filesystem type, block size, label, UUID, and (for NTFS/ext) MFT/superblock locations.

To **mount** a partition (read-only):

```bash
BYTE_OFFSET=$(( OFFSET * 512 ))   # standard sector size
mkdir -p /mnt/evidence
mount -o ro,loop,offset=$BYTE_OFFSET,noexec,nosuid "$IMG" /mnt/evidence
```

Or use kpartx for multi-partition images:

```bash
losetup -fP --read-only "$IMG"
LOOP=$(losetup -j "$IMG" | cut -d: -f1)
ls ${LOOP}p*       # /dev/loop0p1, p2, ...
mount -o ro,noexec,nosuid ${LOOP}p1 /mnt/evidence
```

## File listing and deleted-file markers

```bash
fls -r -p -o $OFFSET "$IMG" | tee output/fls.txt
```

`fls` output convention (the trip-up — `*` prefix means deleted):

| Marker | Meaning |
|---|---|
| `r/r` | regular file (allocated) |
| `d/d` | directory (allocated) |
| `* r/r` | **deleted file** |
| `* d/d` | **deleted directory** |

Filter deleted files:

```bash
grep '^\*' output/fls.txt > output/deleted_files.txt
```

## Recovering files

```bash
# By inode (extract one file)
icat -o $OFFSET "$IMG" <inode> > output/extracted/<filename>

# Bulk recovery — allocated + deleted (-e) or just deleted (omit -e)
mkdir -p output/recovered
tsk_recover -o $OFFSET -e "$IMG" output/recovered

# Inode metadata (timestamps, blocks, NTFS alternate data streams)
istat -o $OFFSET "$IMG" <inode>
```

## Unallocated space and slack

The trip-up: deleted file content often survives only in unallocated space — TSK exposes this via `blkls`, then carve from the resulting blob:

```bash
blkls -o $OFFSET "$IMG" > output/unallocated.bin
strings output/unallocated.bin | grep -iE '(flag\{|ctf\{|password|key)'

# Carve files (PDFs, ZIPs, JPEGs, etc.) from unallocated space only
foremost -i output/unallocated.bin -o output/carved_unalloc 2>/dev/null
cat output/carved_unalloc/audit.txt
```

For file slack (space between EOF and end of allocated cluster), use `blkcat -s`:

```bash
blkcat -s -o $OFFSET "$IMG" <block_number>
```

## Carving from the whole image

```bash
# Header/footer signature carving
foremost -i "$IMG" -o output/foremost -T 2>/dev/null

# Better at fragmented files; supports more formats
photorec /cmd "$IMG" fileopt,everything,enable,search /d output/photorec /log

# Embedded structures (firmware, archives, certs)
binwalk -e -C output/binwalk_extracted "$IMG"
```

## Bulk structured-data extraction

`bulk_extractor` scans the raw image for emails, URLs, IPs, credit cards, EXIF, GPS, etc. — without parsing the filesystem. Useful when the filesystem is damaged or partially overwritten:

```bash
mkdir -p output/bulk
bulk_extractor -o output/bulk "$IMG" 2>&1 | tee output/bulk.log
# Key outputs: email.txt, url.txt, domain.txt, telephone.txt, ccn.txt,
# ip.txt, exif.txt, find.txt, kml.txt (GPS)
```

## Mapping a byte offset back to a file

The trip-up: when you find a flag at byte offset N inside the image (via `grep -ob` or sigfind), use `ifind` to map the block back to its owning inode.

```bash
BLOCK_SIZE=$(grep -i "block size" output/fsstat.txt | head -1 | grep -oE '[0-9]+')
BYTE_OFFSET=<offset>
BLOCK_NUM=$(( BYTE_OFFSET / BLOCK_SIZE - OFFSET ))
ifind -o $OFFSET -d $BLOCK_NUM "$IMG"   # -> inode
icat -o $OFFSET "$IMG" <inode> > output/owner_of_offset.bin
```

`sigfind` searches for hex signatures at expected sector-aligned positions:

```bash
sigfind -o $OFFSET 504B0304 "$IMG"   # ZIP local file headers
sigfind -o $OFFSET FFD8FF "$IMG"     # JPEG SOI
```

## Timeline reconstruction

```bash
fls -r -m "/" -o $OFFSET "$IMG" > output/bodyfile.txt
mactime -b output/bodyfile.txt -d > output/timeline.csv
mactime -b output/bodyfile.txt -d "2024-01-15" "2024-01-16" > output/timeline_window.csv
```

The `macb` column shows which timestamps changed: **m**odified, **a**ccessed, metadata-**c**hanged, **b**orn (created).

## Cleanup

```bash
umount /mnt/evidence 2>/dev/null
losetup -d $LOOP 2>/dev/null
umount /tmp/ewf_mount /tmp/aff_mount 2>/dev/null
```

## Hand-off

For Windows logical images, inventory application artifacts before deep
carving:

```bash
find output/recovered output/extracted -type f \
  \( -iname "*.sqlite" -o -iname "*.db" -o -iname "*.ldb" -o -iname "Local State" \
     -o -iname "Cookies" -o -iname "History" -o -iname "NTUSER.DAT" \
     -o -iname "SYSTEM" -o -iname "SOFTWARE" -o -iname "*.json" \) 2>/dev/null \
  | tee output/high_value_artifacts.txt
```

For DPAPI-backed browser/app secrets, keep the chain explicit: user password or
NT hash, masterkey, Chromium `Local State` key, then the application secret.
Normalize timestamps with the acquired system timezone before building answers.

If extracted files need further analysis (documents, images, executables), apply the **file-repair-and-stego** skill to each. If a memory dump is found within the image, apply **volatility3-memdump**.
