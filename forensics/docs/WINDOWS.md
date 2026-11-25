# Windows Artifact Parser Adapter

## Supported input and prerequisites

The adapter accepts one EVTX file, one Prefetch file, or an extracted `$MFT` file. It runs on Windows only and calls locally installed Eric Zimmerman tools: `EvtxECmd.exe`, `PECmd.exe`, or `MFTECmd.exe`. No tool is downloaded. Registry hive binary parsing, Amcache, LNK/Jump List and JLECmd workflows remain manual. `registry-inspect` maps already parsed registry CSV/JSONL; it is not a hive parser.

## Usage

```powershell
python -m nexsec_dfir windows-artifact C:\Evidence\Security.evtx --kind evtx
python -m nexsec_dfir windows-artifact C:\Evidence\APP.EXE-12345678.pf --kind prefetch
python -m nexsec_dfir windows-artifact 'C:\Evidence\$MFT' --kind mft --max-rows 50000
```

Optional controls: `--timeout` (default 300 seconds), `--max-rows` (default 100,000), and `--output report.json` (must not already exist). Parser CSVs are created in a temporary directory and removed after conversion.

## Expected output

JSON includes source path and SHA-256, parser name, parser export file, source CSV row, the parser row as `observed_value`, and candidate `record_id` / `timestamp_raw` fields when recognized. Timestamp fields are retained raw; the adapter does not guess timezone or event meaning. Output truncation is explicit at the row limit.

## Questions and interpretation

- Execution: Prefetch `LastRun`/run count, Security 4688 or Sysmon 1, BAM and UserAssist. Prefetch alone may not identify a user.
- Logons: Security 4624/4625 and associated SID, logon type, logon ID and source fields.
- Deleted files: MFTECmd `$MFT` records and separate USN/Recycle Bin corroboration. MFT record presence does not prove bytes are recoverable.
- Persistence: registry/service/task artifacts need Registry Explorer/RECmd or another suitable parser; this adapter does not currently parse them.

## Errors and verification

The command fails clearly on non-Windows hosts, missing executable, parser nonzero exit, timeout or missing parser CSV. Verify source SHA-256 before/after, check the parser version/help and compare an event/record ID against the original artifact using a trusted parser. The adapter's candidate field mapping is heuristic; parser CSV headers vary.

## Script blocks and registry exports

```bash
python3 -m nexsec_dfir powershell-reconstruct PowerShell-Operational.csv \
  --event-field EventId --event-id 4104 --write-scripts /case/inert-scripts
python3 -m nexsec_dfir registry-inspect registry-values.csv \
  --key-field KeyPath --name-field ValueName --data-field ValueData \
  --key-contains 'CurrentVersion\\Run'
```

Script block rows are grouped by ID and ordered by `MessageNumber`; missing/conflicting parts remain explicitly incomplete. Output includes source row, event record, timestamp, frame/stream references and export hash when present. Script files are inert and never run. `registry-inspect` preserves the parser row and maps key/name/data fields; specify field names that exist in the selected parser/version.

## Known limitations

Only EVTX, Prefetch and MFT tool modes are wired. Tool output files and tool semantics vary by installed version. No independent raw EVTX/Prefetch/MFT parser is included, and a decoded record does not by itself establish execution, compromise or user attribution.
