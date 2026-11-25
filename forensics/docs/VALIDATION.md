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
| Real memory-image plugin analysis | SKIPPED | No non-sensitive known-answer memory fixture supplied. Installed Volatility exists, but a real dump was not exercised. |
| TShark network adapters | PASS | Mocked parser paths plus installed TShark decoding a generated synthetic DNS PCAP (`a.test`). |
| TSK/libewf adapter | PARTIAL | Mocked partition/extraction checks pass; real `mmls` rejects a synthetic non-disk input cleanly. No real disk image fixture was available; `ewfinfo` absent. |
| Timeline timezone/hash/JSONL | PASS | Synthetic offsets, DST ambiguity, source hash, reference and JSONL record checked. |
| Secure output handling | PASS (covered cases) | Existing no-overwrite/ZIP traversal tests and bounded `icat` output removal/hash tests pass. |
| Full real-world forensic interpretation | NOT TESTED | No public licensed known-answer Windows, RAM or disk datasets were included. |

The test suite reports 30 tests on the current host (including real TShark and TSK rejection tests plus subprocess timeout/output-limit checks; timezone checks cover ambiguous and nonexistent local times). Mock tests establish adapter behavior, not correctness of third-party parsers. No public evidence fixture was downloaded or committed.

## Remaining limitations

- Registry, Amcache, LNK/Jump List and RECmd integration remain manual specialist-tool workflows.
- Windows adapters rely on version-specific parser CSV fields; auto-mapped record/time columns are candidate fields and are not semantically validated.
- TSK offsets and EWF support require analyst confirmation of the actual image sector size and tool build.
- Memory workflows require local symbols and suitable Volatility plugin support; no remote downloads occur.
- Large TShark/Volatility outputs are restricted by packet/timeout and JSON report limits, but parser-specific behavior can still vary.
