# Validation Status

Run from `forensics/`:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q nexsec_dfir tests
python3 -m nexsec_dfir doctor
python3 -m nexsec_dfir --help
```

Status words mean: **PASS** = the specific test ran and met its expected result; **PARTIAL** = only a bounded part was exercised; **SKIPPED** = prerequisites/fixtures were absent; **NOT TESTED** = no evidence was run for the feature.

## Current results (2026-11-25)

| Area | Status | Evidence |
| --- | --- | --- |
| v0.1 regression behavior | PASS | Existing synthetic unittest cases retained and passing. |
| Windows adapter row mapping/error gates | PASS (mock) | Synthetic Zimmerman CSV output, platform gate and parser invocation are tested. |
| Real Windows EVTX/Prefetch/MFT parsing | SKIPPED | Windows host and Zimmerman tools unavailable in this environment. |
| Volatility 3 adapter and offline flag | PASS (mock) | Version capture, JSON output, missing symbols and timeouts tested. |
| Volatility file dump and SHA-1/SHA-256 | PASS (mock) | Synthetic plugin output is copied to a generated-name directory and hashed; no recovered file is executed. |
| Real memory-image plugin analysis | SKIPPED | No non-sensitive known-answer memory fixture supplied. Installed Volatility exists, but a real dump was not exercised. |
| TShark network adapters | PASS | Mocked parser paths plus installed TShark decoding a generated synthetic DNS PCAP (`a.test`). |
| TSK/libewf adapter | PARTIAL | Mocked partition/extraction checks pass; real `mmls` rejects a synthetic non-disk input cleanly. No real disk image fixture was available; `ewfinfo` absent. |
| NTFS named-stream argument handling | PASS (mock) | Exact `fls`-style metadata attribute address, NTFS type and partition-sector offset are passed to `icat`; no real ADS image was available. |
| TSK filesystem-specific inventory | PASS (mock) | Explicit filesystem type and sector offset are passed to `fls` and `fsstat`; no real disk image was used. |
| TSK sector-size forwarding | PASS (mock) | Non-default 4096-byte sectors reach `mmls`, `fsstat`, `fls`, and `icat`; `-o` offsets remain sector counts. |
| VHD detection and qemu-img conversion | PASS / PARTIAL | Mock tests cover unsupported formats, explicit 6 GB cap for a 5 GB image, destination capacity, failed conversion and cleanup; installed qemu-img converts a generated 1 MiB synthetic VHD. No real VHD evidence was used. |
| Base64/XOR/UTF-16LE, EML URLs and script-block reconstruction | PASS (synthetic) | Known-answer byte/text transforms, offline URL extraction, source mutation detection and reordered 4104 message reconstruction tested. |
| EvtxECmd 4104 schema mapping | PASS (synthetic) | A synthetic fixture uses EvtxECmd's standard CSV columns and JSON `Payload`; record IDs, source rows, raw times and source hash are preserved. Unsupported schemas fail explicitly. No Windows event log was parsed. |
| Chunk reconstruction and validation | PASS (synthetic) | Ordering, identical/conflicting duplicates, missing part, expected size/hash, frame/stream references tested. |
| Nested chunk body/outer-field reconciliation | PASS (synthetic) | Matching normalized values merge; differing job, part, total, or data values each raise a conflict error. |
| Timeline timezone/hash/JSONL | PASS | Synthetic offsets, DST ambiguity, source hash, reference and JSONL record checked. |
| Secure output handling | PASS (covered cases) | Existing no-overwrite/ZIP traversal tests and bounded `icat` output removal/hash tests pass. |
| Full real-world forensic interpretation | NOT TESTED | No public licensed known-answer Windows, RAM or disk datasets were included. |

The original v0.2 branch baseline was 41 tests. After review hardening, the suite reports 50 tests on the current host (9 added regression tests; existing tests remain). Real-tool tests decode a generated DNS PCAP with TShark, convert a generated 1 MiB VHD with qemu-img, and check that real `mmls` rejects synthetic non-disk bytes. The 5 GB VHD cap and disk-space paths are mocked; no 5 GB output is created. The EvtxECmd-shaped CSV fixture is synthetic, not a real event log. Mock tests establish adapter argument/error handling, not correctness of third-party parsers. No public evidence fixture was downloaded or committed.

## Remaining limitations

- Raw registry hive, Amcache, LNK/Jump List and RECmd parsing remain specialist-tool workflows; the workbench maps exports and can query Volatility registry plugins where supported.
- Windows adapters rely on version-specific parser CSV fields; auto-mapped record/time columns are candidate fields and are not semantically validated.
- TSK offsets and EWF support require analyst confirmation of the actual image sector size and tool build.
- Memory workflows require local symbols and suitable Volatility plugin support; no remote downloads occur.
- Large TShark/Volatility outputs are restricted by packet/timeout and JSON report limits, but parser-specific behavior can still vary.
