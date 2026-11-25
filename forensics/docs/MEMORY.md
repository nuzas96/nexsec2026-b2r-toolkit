# Memory Forensics Adapter — Volatility 3

## Supported input and prerequisites

Accepts a local memory image readable by the installed Volatility 3 version. The adapter calls `vol` or `volatility3` with `--offline`; remote symbol retrieval is disabled. Symbols must already be available locally. Supported workflows: Windows processes/tree/command-line/network/modules/malfind and Linux processes/tree/command-line (`psaux`)/network/modules/module consistency check.

## Usage

```bash
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-processes
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-tree --timeout 600
python3 -m nexsec_dfir memory-analyze memory.raw --workflow windows-network --output reports/netscan.json
python3 -m nexsec_dfir memory-analyze linux.mem --workflow linux-processes
```

All plugins have a configurable `--timeout` (default 300 seconds) and `--max-output-bytes` (default 4,000,000, separately capped for stdout/stderr). Reaching the output cap terminates the plugin and marks output truncated. `--output` refuses to overwrite an existing report.

## Expected output

JSON contains the source artifact and SHA-256, selected Volatility plugin, JSON records when emitted, otherwise bounded raw tool output, stderr and truncation state. Preserve PID/PPID, timestamps, command line, endpoints, module names and plugin details from the original row. Plugin output fields vary by Volatility version.

## Errors and verification

Missing Volatility, timeout, unsupported plugin, nonzero exit, unavailable symbols and unsupported/corrupt image are reported as errors. Check `vol --help`, local symbol inventory and version; confirm OS/build with a suitable info plugin, then rerun the exact plugin against the same hashed source. No symbols are fetched online.

## Interpretation and limitations

Process or module presence is an observation, not a malware verdict. Compare process trees, command lines, network artifacts and other evidence; account for PID reuse and incomplete acquisitions. `malfind` is a candidate indicator and needs page-level verification. No actual memory dump was included in validation fixtures.
