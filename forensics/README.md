# NEXSEC Advanced Forensics Workbench v0.2 — Evidence-First CTF Forensics

A **standalone, offline-first, question-driven forensic workbench** (Python standard library) for authorized digital-forensics exercises, written separately from the locked B2R toolkit.

**Status:** v0.2 adds specialist-tool subprocess integrations. Adapter logic and existing workflows are covered by synthetic/mock tests; a synthetic DNS capture was also parsed with installed TShark. Windows parsers and genuine disk/memory images were unavailable for real-tool validation on this Linux host. It is **not** a universal forensic parser, automated flag solver or comprehensive incident-response platform. Original evidence is never intentionally overwritten, but **reading a file on a writable filesystem may change access metadata (`atime`)**. For strict forensic acquisition, work from a verified copy or a read-only mounted source as permitted by your lab.

**One-page offline command reference:** [QUICK_COMMANDS.md](QUICK_COMMANDS.md).

## 1. What actually works

| Feature | Command | Behavior / limitations |
| --- | --- | --- |
| Integrity intake | `case-init` | SHA-256, file size, UTC mtime observation, signature clues, private manifest. Refuses recursive outputs and symlink traversal. |
| Integrity recheck | `case-verify` | Recompute original hashes and report UNCHANGED/CHANGED/MISSING/UNVERIFIABLE, never silently PASS. |
| Magic/header triage | `classify` | Identifies common EVTX, registry, Prefetch/MAM, PCAP, SQLite, archive, binary signatures. Unknown remains unknown. |
| ZIP risk inspection | `zip-inventory` | Paths, sizes, CRC metadata, encrypted entries, duplicate names, path traversal, expansion indicators; **no extraction**. |
| Parsed artifact CSV | `csv-inspect` | Search, filter and group existing PECmd/EvtxECmd/MFTECmd CSV exports by exact field names; source row numbers retained. |
| Browser SQLite | `sqlite-inspect` | Inspects schema and up to N sample rows **using a temporary local copy**. Copies WAL/SHM if present. No SQL modifications. |
| String candidates | `hunt` | ASCII/UTF-16LE excerpts with original byte offsets; bounded size/hits and explicit truncated flag. Not malware detection. |
| PCAP metadata | `pcap-summary` | Uses optional `tshark -r`, bounded frames and timeout; counts DNS, HTTP hosts, endpoints, protocols, streams. Not flow reconstruction. |
| PCAP deep triage | `pcap-analyze --mode endpoints/dns/http/tcp/stream/objects` | TShark frame fields retain frame numbers and stream IDs; follow-stream output and HTTP object export are available. Packet cap, timeout and evidence hash checks apply. DNS/connection metadata is not proof of successful transfer. |
| Windows artifacts | `windows-artifact --kind evtx/prefetch/mft` | Windows-host-only adapters for EvtxECmd, PECmd and MFTECmd. Emits parser source row, candidate record/time columns, observed row and source hash. Registry, LNK, Amcache and JLECmd adapters are not yet implemented. |
| Memory | `memory-analyze --workflow ...` | Runs allowlisted Volatility 3 Windows/Linux process, tree, command-line, network, modules or malfind plugins with offline mode. Symbol/plugin failures and timeouts are explicit. |
| Disk image | `disk-analyze --action ...` | Uses TSK `mmls`, `fsstat`, `fls`, `icat` and `ewfinfo` when available. Sector offsets are explicit; extraction is size-capped, hashed and written to a new path. No mounting. |
| Email and encoding | `email-urls`, `decode-value` | Extracts inert message URLs; supports strict Base64, repeating-key XOR and explicit UTF-16LE/UTF-8 decoding. Never executes recovered scripts. |
| PowerShell/Registry exports | `powershell-reconstruct`, `registry-inspect` | Reassembles 4104 parser rows by part metadata and maps registry parser CSV/JSONL fields with record provenance. No raw hive parser is included. |
| Upload chunks | `chunks-reassemble` | Orders parsed JSON chunks, handles exact duplicates, rejects conflicts/missing/invalid Base64, checks optional size/SHA-256, retains frame/stream references. |
| VHD conversion | `vhd-convert` | Uses qemu-img offline for VHD `vpc` to raw conversion, rejects backing-file chains/unsupported formats, checks source hash and enforces an output-size limit. |
| Timestamp correlation | `timeline-build` | Merges parser-exported CSV/JSONL into UTC, preserves source references, flags duplicates and invalid/ambiguous timestamps. |
| Question router | `route` | Transparent keyword rules suggest artifacts, tools, cross-checks and limits. **Does not answer questions**. |
| Findings ledger | `finding-add/list` | Every finding must cite a SHA-256 indexed artifact, source record and observed value; confidence analyst-supplied. |
| Answer syntax check | `answer-check` | Validates hash/IP/SID/hex/timestamp **format only**; cannot verify challenge answer correctness. |
| Environment diagnostics | `doctor` | Checks installed optional forensic tools, never downloads them. |

Core CLI has **zero third-party Python dependencies**. Optional programs such as Volatility 3, TShark, The Sleuth Kit, libewf, Zimmerman's tools, Plaso and Autopsy must be installed or provided independently and are **not** bundled here. Volatility 3 is forced offline. Windows parsers only run on Windows; unsupported hosts report an error.

## 2. Quick start (copy-paste)

Python 3.10+ (3.11+ recommended). Start from the unzipped repository root:

```bash
cd nexsec2026-b2r-toolkit/forensics
python3 -m nexsec_dfir --help
python3 -m nexsec_dfir doctor
```

**Important:** Replace paths below with the files/directories supplied by your *authorized* exercise. Never place your case directory inside the evidence directory.

```bash
# 1. Intake and hash original evidence files (or preferably a read-only acquisition copy)
python3 -m nexsec_dfir case-init --evidence /path/to/EVIDENCE --case /path/to/CASE-001

# 2. Read the manifest, with hashes and detected formats
python3 -m json.tool /path/to/CASE-001/manifest.json

# 3. Check integrity at any later time
python3 -m nexsec_dfir case-verify --case /path/to/CASE-001

# 4. Route an actual question to artifact leads (NOT the answer)
python3 -m nexsec_dfir route 'Which executable ran last and at what time?'

# 5. Investigate the appropriate supplied artifact, for example
python3 -m nexsec_dfir classify /path/to/EVIDENCE/suspect.pf
python3 -m nexsec_dfir zip-inventory /path/to/EVIDENCE/archive.zip
python3 -m nexsec_dfir hunt /path/to/EVIDENCE/suspect.bin --max-bytes 100000000

# 6. Record a defensible finding using the exact relative_path from manifest
python3 -m nexsec_dfir finding-add --case /path/to/CASE-001 \
  --artifact 'suspect.pf' --source-ref 'PECmd export row 17' \
  --observed 'Run time displayed as 2026-10-26T23:06:40Z' \
  --interpretation 'Parser reports program run time; corroboration pending' \
  --confidence supported-inference --question 'What time did it run?'
```

The last command is a **sample**, not a real forensic finding. You must derive the observed value from actual evidence and parser output; no flag or result is generated automatically.

## 3. Special tools / advanced workflow

### Investigate a specific EVTX/Prefetch/MFT CSV export

CSV schemas vary by tool and version. First display exact column headers, then filter/group by fields that really exist:

```bash
python3 -m nexsec_dfir csv-inspect /path/to/evtx-export.csv --limit 3
python3 -m nexsec_dfir csv-inspect /path/to/evtx-export.csv \
  --field EventId --equals 4624 --select TimeCreated,EventId,UserName \
  --group-field UserName --limit 25
```

The CSV reader is read-only and displays `source_row` for traceability. It scans up to 250,000 rows by default; increase `--max-rows` only where needed. It does not parse original EVTX files.

### Browser and SQLite

```bash
python3 -m nexsec_dfir sqlite-inspect /path/to/History --table downloads --limit 25
```

If the browser database has `History-wal` and `History-shm`, place all three source files together so the tool can copy the sidecars. If artifacts were acquired non-atomically, missing WAL entries are possible. Chrome timestamps commonly use microseconds since 1601; **confirm the specific column's epoch** before conversion.

### PCAP and packet metadata

```bash
python3 -m nexsec_dfir pcap-summary /path/to/traffic.pcapng --max-packets 50000 \
  --output /path/to/CASE-001/reports/pcap-summary.json
```

`tshark` must already be installed. This creates a summary of **up to** 50,000 decoded frames. The `possibly_truncated` field warns if a frame cap was reached. A DNS query or TCP stream count is not proof of data exfiltration.

### Timeline from existing parser exports

Set up a JSON file specifying each source, format, exact timestamp field and encoding. A sample manifest and sample data are in `examples/`.

```bash
python3 -m nexsec_dfir timeline-build \
  --manifest examples/timeline_sources.json \
  --output /path/to/CASE-001/reports/timeline.csv
```

A separate `.errors.jsonl` records malformed/ambiguous rows. Supported time encodings: `iso`, `unix_s`, `unix_ms`, `filetime_100ns`, `webkit_us`. ISO values **without a timezone** require an explicit `assume_timezone` in the input manifest, e.g. `Asia/Kuala_Lumpur` or `UTC`. Timestamps are always retained as raw strings too. Duplicate matching rows are **flagged, not deleted**.

### Answer syntax only

```bash
python3 -m nexsec_dfir answer-check --type timestamp --value '2026-10-26T23:06:40Z'
python3 -m nexsec_dfir answer-check --type sha256 --value 'PUT_64_HEX_DIGITS_HERE'
```

An answer passing the check can still be wrong. Look at the forensic source and expected challenge format first.

## 4. Question-driven reference playbooks

- [Question-to-evidence decision tree](docs/QUESTION_WORKFLOW.md)
- [Windows EVTX, Prefetch, MFT, Registry and user attribution](docs/WINDOWS.md)
- [PCAP and network investigation](docs/NETWORK.md)
- [Memory/Volatility 3 investigation](docs/MEMORY.md)
- [Disk, E01, partition and deleted-file analysis](docs/DISK.md)
- [Browser/SQLite, file recovery and archive pitfalls](docs/BROWSER_FILES.md)
- [Tool checklist and known validation limits](docs/VALIDATION.md)

These documents contain manual investigation reference commands. They are **not** automatically executed by the toolkit, and tools/flags may differ by installed version. Check official help before running commands.

## 5. Run synthetic regression tests

```bash
python3 -m unittest discover -s tests -v
```

Tests run on isolated temporary synthetic files, without network access or exercise evidence. External tools are mocked except for a real TShark integration test that generates a synthetic DNS PCAP when TShark is installed. A PASS does not validate interpretation of real EVTX/MFT/Prefetch, memory or disk evidence.

## 6. Safe handling rules

- Never execute malware samples or mount writable filesystem images on your analysis host.
- Verify hashes of originals and derived copies; do not publish evidence, login data or case outputs.
- Use parser outputs as leads with precise record numbers, original timestamps, timezone, source file hashes and notes.
- `.csv` output defangs formula-like strings for spreadsheet safety; exact raw evidence values must be checked in source records, not inferred from formatted export.
- ZIP inventory does not extract or validate CRC by reading content; suspicious members must be handled with a separate approved process on a copy.
- SQLite copying is not atomic if another process is still writing the database; ensure static/forensic acquisition where possible.
- A keyword-routed candidate is not a factual finding. A suspicious file, user, key, process, IP or URL is not proof of malicious activity without corroboration.

**No AI, API keys, remote uploads or network requests are used by this software.** This is a local tool; always follow the access, tool and evidence rules established by your exercise organizer.

## 7. Advanced references

- [Advanced troubleshooting](docs/TROUBLESHOOTING.md)
- [Validation report and PASS/PARTIAL/SKIPPED status](docs/VALIDATION.md)
- [Quick commands](QUICK_COMMANDS.md)
