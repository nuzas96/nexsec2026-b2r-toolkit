# Release Notes — v0.2.0

## Implemented

- Preserved v0.1 intake, hashing, verification, classification, SQLite/CSV/archive inspection, strings hunting, findings ledger, answer syntax checks and CLI commands.
- Added Windows-host-only adapters for EvtxECmd, PECmd and MFTECmd with source artifact/hash, parser-export row, candidate record/time fields and observed values.
- Added allowlisted Volatility 3 Windows/Linux process, process-tree, command-line, network, module and malfind workflows, forced to offline mode.
- Extended TShark workflows to endpoint, DNS, HTTP, TCP frame records, TCP follow-stream output and HTTP object extraction.
- Added The Sleuth Kit partition, filesystem, file-list and bounded file extraction workflows plus libewf `ewfinfo` support.
- Added richer deterministic question routes, timeline JSONL, source hashes, original timezone labels, DST ambiguity detection and a structured investigative summary.
- Added mocked tool tests and a real TShark integration test using a generated DNS capture.

## Validation status

- **PASS:** 30 unit/mock tests and synthetic end-to-end checks.
- **PASS:** real TShark decode of a generated one-query DNS PCAP.
- **SKIPPED:** real Windows parser tests; Zimmerman tools were unavailable and this host is Linux.
- **SKIPPED:** real memory/disk image parsing; no licensed known-answer fixtures were present.
- **PARTIAL:** TSK adapter mock/extraction tests pass and real `mmls` rejects an unsupported synthetic input; no real disk image was used.

See [docs/VALIDATION.md](docs/VALIDATION.md) for test commands and remaining limitations.
