# Practice Workflow: Linked Windows Memory Questions

This is a generic multi-question memory workflow using placeholders only. It does not contain challenge answers or presume that a process/file is malicious.

## 1. Establish image support and process context

```bash
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-processes
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-tree
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-command-line
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-scan-processes
```

The Volatility adapter records its version, runs offline, and reports symbol/plugin failures. Compare active and scanned process views, parent PID, image path, command line and timestamps. PID relationships and names are leads; validate against the dump and other logs.

## 2. Correlate network artifacts

```bash
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-network
```

Map endpoint records to process identifiers and command lines when available. A connection artifact does not prove successful C2 or exfiltration. Confirm with packet/log evidence, direction, bytes, response and time.

## 3. Scan and dump files safely

```bash
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-file-scan
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-dumpfiles \
  --dump-dir /case/memory-dumps --pid <pid> --dump-filter 'filename-regex' \
  --max-dump-bytes 100000000
```

`windows.dumpfiles` writes first to a temporary directory. A directory-size watcher stops the plugin at the configured cap; dumps are copied to the new case directory only after successful completion and SHA-1/SHA-256 are computed. Output filenames are generated locally, original tool names remain in the report, and no file is executed. A memory dump can contain only partial cached pages; compare hashes and file structure against other recovered copies.

## 4. Inspect registry hives, persistence and account evidence

```bash
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-registry-hives
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-registry-key \
  --registry-key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-registry-key \
  --registry-key 'SAM\\Domains\\Account\\Users'
```

Use the hive list and exact key/value rows to identify which user hive and account records are present. Volatility output remains parser evidence; value presence alone does not show execution or account creation timing. Correlate SID/name, process, authentication events and timestamps from independent artifacts.

## 5. Check hashes and repository clues

Each dumped file report includes SHA-1 and SHA-256. For additional bounded string triage:

```bash
python3 -m nexsec_dfir hunt /case/memory-dumps/dump-0001.bin --max-bytes 100000000
python3 -m nexsec_dfir classify /case/memory-dumps/dump-0001.bin
```

Repository URLs, strings, filenames and hashes are observed clues, not proof of origin or maliciousness. Verify any attribution against the precise recovered artifact and independent metadata.

## 6. Link questions without collapsing confidence

Export relevant parser rows to JSONL/CSV and feed them to `timeline-build` with explicit time encodings. Keep process, network, registry, file and account records linked by source hashes and plugin references. Use `finding-add` for each question and `investigative-summary` to keep confirmed observations, supported inferences, hypotheses and unknowns separate. The workbench does not solve a set of questions automatically.
