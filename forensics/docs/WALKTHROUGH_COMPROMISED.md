# Practice Workflow: Windows Phishing, PowerShell, Persistence and Upload Chunks

This playbook uses only placeholders and generic artifacts. It contains no challenge key, filename, credential or answer.

## 1. Intake and identify the VHD

```bash
python3 -m nexsec_dfir case-init --evidence /lab/evidence --case /lab/case
python3 -m nexsec_dfir classify /lab/evidence/disk.vhd
python3 -m nexsec_dfir vhd-convert /lab/evidence/disk.vhd \
  --raw-output /lab/case/disk.raw --max-output-bytes 100000000000
python3 -m nexsec_dfir case-verify --case /lab/case
```

Conversion accepts QEMU's `vpc` VHD format, rejects other formats/backing files, enforces a virtual-size cap, writes a new raw image, and checks the source hash before/after. Keep the original VHD and conversion report; analyze only the new raw image.

## 2. Inspect email links without opening them

```bash
python3 -m nexsec_dfir email-urls /lab/evidence/message.eml --decode-param <parameter-name>
```

Use the exact parameter name observed in the message. This command extracts strings and an optional Base64 preview; it does not navigate to the link. If the parameter contains an encoded binary or multiple transform layers, save the value to a text file and use `decode-value` with transforms justified by the evidence.

## 3. Parse Windows event and filesystem artifacts

On a Windows analysis host with Zimmerman tools installed:

```powershell
python -m nexsec_dfir windows-artifact C:\Evidence\PowerShell-Operational.evtx --kind evtx
python -m nexsec_dfir powershell-reconstruct C:\Case\exports\events.csv \
  --event-field EventId --event-id 4104 --write-scripts C:\Case\scripts-inert
```

Review complete/incomplete script blocks, message numbers, record IDs and timestamps. Exported script files are inert evidence. Never invoke PowerShell on them. Decode an observed `-EncodedCommand` independently:

```bash
python3 -m nexsec_dfir decode-value --value '<observed-base64>' --base64 --text-encoding utf-16le
```

For Run key and account questions, use a suitable offline registry parser to produce a CSV/JSONL value export, then inspect exact key/name/data fields:

```bash
python3 -m nexsec_dfir registry-inspect registry-values.csv \
  --key-field KeyPath --name-field ValueName --data-field ValueData \
  --key-contains 'CurrentVersion\\Run'
```

The workbench maps parser exports; it does not parse hive binaries or assert that a value executed. Correlate user hive, SID, event records and timestamps.

## 4. Examine alternate data streams

```bash
python3 -m nexsec_dfir disk-analyze /lab/case/disk.raw --action files --offset <partition-sector>
python3 -m nexsec_dfir disk-analyze /lab/case/disk.raw --action extract \
  --offset <partition-sector> --filesystem ntfs --inode '<metadata-address-from-fls>' \
  --extract-to /lab/case/stream.bin --max-bytes 50000000
```

On NTFS, `fls` may list a stream as a metadata address like `MFT-entry-attribute-type-attribute-id`; pass the exact stream attribute address to `icat`, not just the base file record. The byte stream's completeness must be checked. Hash the extracted content; do not execute it.

## 5. Reassemble parsed upload chunks

First produce bounded HTTP/JSON frame records from the PCAP and inspect the exact JSON structure, `job`, `part`, `total`, Base64 `data`, frame number and TCP stream. Flatten nested JSON to JSONL if necessary, preserving original frame/stream references. Then:

```bash
python3 -m nexsec_dfir chunks-reassemble upload-records.jsonl \
  --reassembled-output /lab/case/upload.bin --job '<observed-job-id>' \
  --expected-size <size-if-known> --expected-sha256 <digest-if-known>
```

Conflicting duplicate chunks, missing parts and invalid Base64 stop reconstruction. Identical duplicate parts are recorded and counted once. A local complete payload does not prove the server accepted or retained it; verify request/response status and both directions in the PCAP.

## 6. Correlate and record

Build a timeline from parsed records with explicit encodings/timezones. Record source record IDs, parser version, hashes, frame/stream references and alternative explanations. Keep observations separate from supported inferences and hypotheses. No step in this workflow yields an answer automatically.
