# Release Notes — v0.1.0

**Scope:** implemented as a standalone local Python workbench, separate from the existing B2R repository. The output is an installable source ZIP, not an update to a user's GitHub repository.

## Implemented

- `case-init` and `case-verify`: source integrity SHA-256, detection and completeness notes.
- Signature classification and bounded ZIP inventory; no automatic extraction.
- SQLite copy-based schema and sample row inspection, basic ASCII/UTF-16LE string hunt.
- TShark-dependent PCAP metadata summary; no packet payload reconstruction.
- CSV inspection/search/grouping of existing specialist-parser exports.
- Multi-source timeline conversion with explicit time encodings, UTC, source references, duplicate warnings and invalid-row log.
- Rule-based question routing, source-bound analyst findings ledger, syntax-only answer checks.
- Seven specialist documentation pages and one-page offline quick command sheet.

## Validation

- Unit tests and end-to-end CLI checks performed with synthetic input only.
- No live Windows EVTX/Prefetch/MFT decode, E01/RAW image recovery, real RAM dump analysis, or real PCAP analysis was claimed.
- Optional forensic dependencies are not bundled; check `doctor`.

## Limitations and next stage

To reach an advanced **validated** toolchain, integrate actual offline specialist parsers and validate each against known-answer datasets, especially MAM Prefetch, Windows security EVTX, MFT/USN records, Chrome WAL, realistic RAM dumps and mixed PCAP flow reconstruction. Do not use a heuristic keyword suggestion as evidence. Always comply with the evidence collection and tool rules of the environment.
