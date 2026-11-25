# Release Notes — v0.2.0

## Implemented

- Preserved v0.1 intake, hashing, verification, classification, SQLite/CSV/archive inspection, strings hunting, findings ledger, answer syntax checks and CLI commands.
- Added Windows-host-only adapters for EvtxECmd, PECmd and MFTECmd with source artifact/hash, parser-export row, candidate record/time fields and observed values.
- Added allowlisted Volatility 3 Windows/Linux process, process-tree, command-line, network, module and malfind workflows, forced to offline mode.
- Extended TShark workflows to endpoint, DNS, HTTP, TCP frame records, TCP follow-stream output and HTTP object extraction.
- Added The Sleuth Kit partition, filesystem, file-list and bounded file extraction workflows plus libewf `ewfinfo` support.
- Added VHD `vpc` detection/conversion to raw through qemu-img, strict Base64/repeating-XOR/UTF-16LE decoding, offline EML URL extraction, 4104 script-block reconstruction, and registry export field mapping.
- Added bounded chunked JSON upload reconstruction with duplicate/conflict/missing-part handling, expected size/hash checks and frame/stream references.
- Extended Volatility with process scan, file scan/dump, registry hive and key/value plugins; recovered files are copied to isolated directories with SHA-1/SHA-256.
- Added richer deterministic question routes, timeline JSONL, source hashes, original timezone labels, DST ambiguity detection and a structured investigative summary.
- Added mocked tool tests and a real TShark integration test using a generated DNS capture.
- Hardened TSK device-sector-size forwarding across partition, filesystem, listing and extraction commands; sector offsets remain explicit `-o` values.
- Raised the finite VHD conversion default to 10 GB, added destination free-space checks with a 64 MiB reserve, and covered explicit larger caps and failure cleanup.
- Reject conflicting nested JSON/body and outer CSV/JSONL values for chunk metadata or data.
- Added EvtxECmd-shaped `Payload` JSON mapping for 4104 script blocks, explicit unsupported-schema errors, and source record provenance checks.

## Validation status

- **PASS:** 50 tests total (41-test baseline plus 9 regression tests).
- **PASS:** real TShark decode of a generated one-query DNS PCAP.
- **PASS:** real qemu-img conversion of a generated 1 MiB VHD fixture; no real VHD evidence was used.
- **PASS (mock):** disk sector-size flags/sector offsets, 5 GB virtual-image cap with an explicit higher bound, insufficient-space rejection, and temporary/final-output cleanup paths.
- **PASS (synthetic):** nested chunk merge conflicts and EvtxECmd `Payload` schema mapping; no real EVTX file was parsed.
- **SKIPPED:** real Windows parser tests; Zimmerman tools were unavailable and this host is Linux.
- **SKIPPED:** real memory/disk image parsing; no licensed known-answer fixtures were present.
- **PARTIAL:** TSK adapter mock/extraction tests pass and real `mmls` rejects an unsupported synthetic input; no real disk image was used.
- **PARTIAL:** Decoder, EML, script-block, registry-export, chunk and Volatility dump workflows have synthetic/mock validation only; no real challenge artifact was used. qemu-img ran against a generated VHD fixture only.

See [docs/VALIDATION.md](docs/VALIDATION.md) for test commands and remaining limitations.
