# Offline Copy-Paste Quick Commands — NEXSEC Forensics v0.2

Start in the unzipped folder. Replace `EVIDENCE` and `CASE` with **authorized local paths**; never write a case directory inside the original evidence tree. This is a guide, not a challenge answer.

## Intake and verification (always first)

```bash
python3 -m nexsec_dfir doctor
python3 -m nexsec_dfir case-init --evidence /path/EVIDENCE --case /path/CASE
python3 -m json.tool /path/CASE/manifest.json
python3 -m nexsec_dfir case-verify --case /path/CASE
```

## Determine likely artifacts for a question

```bash
python3 -m nexsec_dfir route 'What time was the executable last run?'
python3 -m nexsec_dfir route 'Which IP received an uploaded file?'
python3 -m nexsec_dfir route 'What deleted file can be recovered from NTFS?'
```

## Classify and inspect common evidence

```bash
python3 -m nexsec_dfir classify /path/EVIDENCE/unknown.bin
python3 -m nexsec_dfir zip-inventory /path/EVIDENCE/archive.zip
python3 -m nexsec_dfir hunt /path/EVIDENCE/suspicious.bin --max-hits 100
python3 -m nexsec_dfir sqlite-inspect /path/EVIDENCE/History
python3 -m nexsec_dfir sqlite-inspect /path/EVIDENCE/History --table downloads --limit 30
python3 -m nexsec_dfir pcap-summary /path/EVIDENCE/capture.pcapng --max-packets 50000
```

## Advanced network, Windows, memory and disk adapters

```bash
python3 -m nexsec_dfir pcap-analyze /path/EVIDENCE/traffic.pcapng --mode dns --max-packets 10000
python3 -m nexsec_dfir pcap-analyze /path/EVIDENCE/traffic.pcapng --mode http --max-packets 10000
python3 -m nexsec_dfir pcap-analyze /path/EVIDENCE/traffic.pcapng --mode stream --stream-id 3
python3 -m nexsec_dfir pcap-analyze /path/EVIDENCE/traffic.pcapng --mode objects \
  --output-dir /path/CASE/objects --max-packets 10000

# Windows only; Zimmerman tools must be installed and available on PATH.
python3 -m nexsec_dfir windows-artifact /path/EVIDENCE/Security.evtx --kind evtx
python3 -m nexsec_dfir windows-artifact /path/EVIDENCE/example.pf --kind prefetch
python3 -m nexsec_dfir windows-artifact '/path/EVIDENCE/$MFT' --kind mft

# Volatility 3 runs explicitly offline; required symbols must already be available.
python3 -m nexsec_dfir memory-analyze /path/EVIDENCE/memory.raw --workflow windows-processes
python3 -m nexsec_dfir memory-analyze /path/EVIDENCE/memory.raw --workflow windows-network

# Sleuth Kit offsets are sectors. Extraction output must be a new path.
python3 -m nexsec_dfir disk-analyze /path/EVIDENCE/disk.dd --action partitions --sector-size 512
python3 -m nexsec_dfir disk-analyze /path/EVIDENCE/disk.dd --action files --offset 2048
python3 -m nexsec_dfir disk-analyze /path/EVIDENCE/disk.dd --action extract \
  --offset 2048 --inode 42 --extract-to /path/CASE/recovered.bin --max-bytes 50000000
```

Object and disk extraction write to new separate paths. Hash and inspect recovered data; never execute it. See [advanced troubleshooting](docs/TROUBLESHOOTING.md).

## Search imported artifact-parser CSVs (PECmd / EvtxECmd / MFTECmd)

```bash
python3 -m nexsec_dfir csv-inspect /path/CASE/exports/events.csv --limit 5
python3 -m nexsec_dfir csv-inspect /path/CASE/exports/events.csv \
  --field EventId --equals 4624 --group-field UserName --limit 30
```

First inspect header fields and adjust names; parser CSV columns vary by tool/version. No direct raw EVTX parsing is done by this tool.

## Sort and merge timeline exports

```bash
python3 -m nexsec_dfir timeline-build \
  --manifest examples/timeline_sources.json \
  --output /path/CASE/reports/timeline.csv
```

`examples/timeline_sources.json` is a **synthetic sample**. Replace source paths and field mapping for your real parser exports. Invalid and ambiguous timestamps go to `.errors.jsonl`, not silently dropped. Use a `.jsonl` output suffix for chronological JSONL.

## Verify answer format and save a sourced finding

```bash
python3 -m nexsec_dfir answer-check --type timestamp --value '2026-10-26T23:06:40Z'
python3 -m nexsec_dfir finding-add --case /path/CASE \
  --artifact 'example.evtx' --source-ref 'EventRecordID=123' \
  --observed 'actual source record value here' \
  --interpretation 'what this supports, with limitations' \
  --confidence supported-inference --question 'What happened?'
```

The `--artifact` must **exactly match a relative_path in CASE/manifest.json** and its SHA-256 must still match intake. `answer-check` validates syntax only, never correctness.

The workflow is: intake and hash → identify artifact → route question → run parser → preserve record references → correlate → verify → record the answer and remaining unknowns. `investigative-summary --case /path/CASE --unknown 'Was the transfer successful?'` groups ledger observations, inferences and hypotheses without elevating them.

## Specialist tool handoff

- Windows: `docs/WINDOWS.md` (PECmd, EvtxECmd, MFTECmd, Registry, execution semantics)
- Disk: `docs/DISK.md` (mmls, fls, fsstat, icat, EWF/E01)
- Memory: `docs/MEMORY.md` (Volatility 3)
- PCAP: `docs/NETWORK.md` (TShark/Wireshark)
- Browser, archives, unknown evidence: `docs/BROWSER_FILES.md`

No evidence is uploaded to any cloud; optional programs must exist locally. Keep source media read-only and reports in a separate work directory.
