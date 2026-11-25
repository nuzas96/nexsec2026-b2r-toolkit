# Validation Status, Limits, and Roadmap

## Confirmed by synthetic tests

Run: `python3 -m unittest discover -s tests -v`.

Synthetic test classes verify: signature classification, intentional unknown result, original SHA-256 preservation, changed-file detection, case destination protections, no symlink traversal, ZIP traversal/duplicate flags, SQLite read from a copy, bounded ASCII/UTF-16LE hunt, Windows FILETIME + WebKit + local timezone normalization, rejection of naive timestamps, timeline duplicate/malformed row logging, rule-based routing and answer format checks, and exported CSV filtering/grouping with source row indices.

**What PASS means:** these specific algorithmic properties worked on controlled files. It does **not** mean the workbench independently interprets compressed Prefetch internals, EVTX, Windows Registry, MFT, E01, RAM or network application payloads.

## Explicitly unverified or delegated

| Area | Status | Reason |
| --- | --- | --- |
| Real Windows compressed Prefetch parsing | External-tool only | Needs PECmd and known ground-truth fixture |
| Windows EVTX / Sysmon mapping | External-tool only | Needs event parser and known record mappings |
| NTFS MFT/USN and E01 | External-tool only | Needs The Sleuth Kit / libewf and disk fixtures |
| Memory plugins | External-tool only | Needs Volatility 3, symbols and genuine memory fixtures |
| PCAP summary CLI | TShark-dependent | Adapter requires compatible installed TShark + real capture fixture |
| SQLite live WAL correctness | Partial | Non-atomic source copying may miss concurrent writes |
| Timeline timezone/DST | Partial | Ambiguous local clock times require analyst verification |
| Malware identification | Not implemented | String hits/header detection are not malware verdicts |
| Full automated flag solving | Not implemented | The question router only recommends investigation paths |

## Quality gates for later phases

- Produce small legally reusable known-answer Windows/PCAP/disk/memory fixtures.
- Test each external parser invocation on fixture datasets and compare expected output row-by-row.
- Add explicit error-classification and log source citations for parser failures.
- Introduce a file-backed configuration mapping export schemas by parser version rather than guessing CSV headers.
- Verify extraction/source hashes on any recovered file and ensure no write to original is possible under target OS permissions.
- Add integration tests for genuine TShark output and realistic large-file performance.

## Sources for additional tools

- Zimmerman Tools: https://ericzimmerman.github.io/
- Sleuth Kit: https://www.sleuthkit.org/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Wireshark/TShark: https://www.wireshark.org/docs/
- Plaso: https://plaso.readthedocs.io/

This document is a validation inventory, not a certificate of forensic soundness.
