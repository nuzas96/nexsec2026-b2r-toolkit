# Disk & Deleted-File Forensics — TSK + EWF

Use original evidence read-only or a verified forensic copy. A filename ending `.dd` is not sufficient evidence of image type; inspect signatures and layout.

## Partitioned raw image

```bash
mmls evidence.dd
```

From output, record **Start sector** and **sector size**; TSK `-o` expects a *sector offset*, not byte offset.

```bash
# Example only: replace 2048 with observed partition start in SECTORS.
fsstat -o 2048 evidence.dd
fls -r -o 2048 evidence.dd

# Replace INODE_RECORD with the recovered metadata address.
# Output must be in a working/output directory, not the input image.
icat -o 2048 evidence.dd INODE_RECORD > /path/to/CaseOut/recovered.bin
sha256sum /path/to/CaseOut/recovered.bin
```

The example offset is illustrative and may be wrong for your image. Look for ADS/forks on NTFS as applicable, deleted metadata, timestamps and extent mapping. `icat` may produce partial or stale bytes if blocks were reused.

## For E01/EWF

```bash
ewfinfo evidence.E01
```

Use a properly supported, read-only EWF access method or forensic GUI. Account for multipart EWF sets; image size and hash must be checked against acquisition metadata. Do not run a generic file extractor on evidence unless the tool supports the format.

## Forensics rigor

- Preserve original image hashes and command output/logs.
- MFT/USN timestamps have different meanings; consult file record metadata and associated journal events.
- A deleted file's name and its recovered bytes may come from different surviving structures and require independent validation.
- A volume filesystem image may have no partition table; `mmls` is not always meaningful.

Official reference: https://www.sleuthkit.org/sleuthkit/
