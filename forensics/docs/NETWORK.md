# Network Forensics — TShark

## Supported input and prerequisites

Accepts an offline PCAP/PCAPNG file readable by installed `tshark`. No live capture, network request or upload is performed.

## Usage

```bash
python3 -m nexsec_dfir pcap-summary traffic.pcapng --max-packets 50000
python3 -m nexsec_dfir pcap-analyze traffic.pcapng --mode endpoints --max-packets 10000
python3 -m nexsec_dfir pcap-analyze traffic.pcapng --mode dns --max-packets 10000
python3 -m nexsec_dfir pcap-analyze traffic.pcapng --mode http --max-packets 10000
python3 -m nexsec_dfir pcap-analyze traffic.pcapng --mode tcp --max-packets 10000
python3 -m nexsec_dfir pcap-analyze traffic.pcapng --mode stream --stream-id 3
python3 -m nexsec_dfir pcap-analyze traffic.pcapng --mode objects \
  --output-dir /case/objects --max-packets 10000
```

`--timeout` defaults to 180 seconds. Packet caps are configurable up to 100,000 for detailed modes. `--max-output-bytes` caps captured TShark stdout/stderr and terminates decoding when reached; the report marks truncated output. Object extraction requires a new, separate output directory; the source capture is never used as an output location.

## Expected output

Frame records include frame numbers and selected fields: timestamps as raw epoch strings, endpoints, protocol, DNS questions/answers/rcode, HTTP methods/host/URI/status/content length, TCP stream ID/ports/length/flags. Stream mode returns TShark's formatted follow-stream view. Object mode returns each extracted object's path, byte size and SHA-256. `pcap-summary` returns endpoint/protocol/domain/host/stream counts.

## Errors and verification

Missing TShark, malformed captures, timeouts, nonzero exits and output collisions are explicit errors. Verify the evidence SHA-256, capture completeness and stream ID; compare relevant frames in Wireshark and inspect both directions, protocol response/status and reconstructed object hash. TShark display filters and field availability can vary by version.

## Interpretation and limitations

A DNS request does not establish resolution, connection or transfer. A TCP stream or byte count does not establish file exfiltration. HTTP export can reconstruct only supported unencrypted/decrypted objects. Exported files are untrusted and never opened or executed by the adapter. Stream/export output is tool-formatted and should be independently reviewed.
