# Advanced Troubleshooting

## Start with source integrity

Run `doctor`, intake evidence into a separate case directory, and record the SHA-256. Each external adapter rechecks the source hash after successful parsing and stops if it changed. Reading evidence can still update filesystem access metadata; use a verified copy or read-only source where required. Never save reports beneath the evidence tree.

## Tool availability and platform

- `doctor` only checks PATH and does not install tools.
- `windows-artifact` requires Windows and the matching `EvtxECmd.exe`, `PECmd.exe` or `MFTECmd.exe`.
- Volatility must be available as `vol` or `volatility3`; its plugin list and renderer vary by version.
- TShark requires local Wireshark/TShark installation.
- TSK actions require the matching `mmls`, `fsstat`, `fls` or `icat`; EWF metadata requires `ewfinfo`.

## Parser failures

1. Re-run the parser's own `--help` or version command and check that this file type is supported.
2. Confirm the evidence hash and magic bytes; filenames/extensions are not authoritative.
3. For Volatility, confirm image format and OS/build; use offline symbols already installed. Missing symbols are an unresolved requirement, not evidence of an empty image.
4. For TSK, verify the sector size and sector offset. `--offset` is in sectors. A volume image may not have a partition table.
5. For Windows CSV exports, inspect actual field names. Candidate `timestamp_raw`/`record_id` mapping is best-effort; preserve and review the entire `observed_value` row.
6. Reduce `--max-packets`, `--max-rows`, `--max-bytes` or `--max-output-bytes`, or increase `--timeout` deliberately. Partial/truncated output must not be treated as a complete inventory.

## Output handling

Reports refuse overwrite. TShark object export and disk extraction require a fresh separate output path. If a parser exits midway, inspect any partial output before retrying; do not treat it as complete. Hash reconstructed objects and compare with protocol metadata. Never execute recovered executables or scripts.

## Interpretation checks

- Keep observation, supported inference, hypothesis and unknown separate in `investigative-summary`.
- A DNS query, TCP connection, `malfind` page, Amcache entry, Prefetch file, MFT deleted flag or persistence key is not by itself proof of malicious action.
- Preserve raw timestamp and timezone; ambiguous daylight-saving local times are rejected and must be resolved from source context.
- Correlation keys group records for review only. Timeline order or proximity does not establish causation.
