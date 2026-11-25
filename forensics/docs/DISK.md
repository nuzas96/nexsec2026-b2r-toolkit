# Disk & Deleted-File Forensics — Sleuth Kit and libewf

## Supported input and prerequisites

Accepts a raw image or a format understood by the installed TSK tool. E01 metadata uses `ewfinfo` if installed; image-set handling depends on local libewf/TSK support. Commands read evidence only; no mounting is performed. TSK and optionally libewf must be installed locally.

## Usage

```bash
python3 -m nexsec_dfir disk-analyze disk.E01 --action ewf-info
python3 -m nexsec_dfir disk-analyze disk.dd --action partitions --sector-size 512
python3 -m nexsec_dfir disk-analyze disk.dd --action filesystem --offset 2048
python3 -m nexsec_dfir disk-analyze disk.dd --action files --offset 2048
python3 -m nexsec_dfir disk-analyze disk.dd --action extract --offset 2048 \
  --inode 1234 --extract-to /case/recovered.bin --max-bytes 50000000
```

`--offset` is a sector offset, not a byte offset. `--sector-size` applies to the `mmls` partition inventory where requested. Extraction requires a new `--extract-to` path and defaults to a 50 MB cap; `--timeout` defaults to 300 seconds.

## Expected output

Partition, filesystem and listing actions return the installed tool's text output along with source path/hash, action, sector offset/size, tool name and truncation indication. `icat` extraction returns output path, byte size and SHA-256. Preserve the original inode/record identifier and verify extracted bytes separately.

## Errors and verification

Missing utility, unsupported format, bad offset, timeout, nonzero TSK exit, output collision, source hash change and extraction size overflow fail explicitly. Verify image format, acquisition sector size, partition start sector and filesystem before using offsets; reconcile the result with independent image metadata and compare source hash after analysis.

## Known limitations

No image fixture was available for real TSK validation. `ewfinfo` only inventories EWF metadata; it does not convert or mount. TSK support for EWF depends on build options. Deleted records can lack recoverable data, and file name/metadata may not correspond to recovered content. A successful extraction does not establish the file's original completeness or semantics.
