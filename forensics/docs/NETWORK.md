# Advanced Network & PCAP Forensics Playbook

Only inspect assigned PCAP/PCAPNG evidence. TShark uses `-r` for an existing capture; no live sniffing or network access is performed by these commands.

## 1. Preflight

```bash
file traffic.pcapng
tshark -r traffic.pcapng -q -z io,phs
```

If protocol decoding is incomplete, inspect encapsulation/tunnels, capture truncation, TCP reassembly settings and encrypted traffic rather than assuming "no activity".

## 2. Enumerate conversations / endpoints

```bash
tshark -r traffic.pcapng -q -z conv,tcp
tshark -r traffic.pcapng -q -z endpoints,ip
```

Conversation bytes are not automatically an exfiltration verdict. Note direction, initiator, failed handshakes and whether network capture contains full sessions.

## 3. DNS and HTTP evidence

```bash
tshark -r traffic.pcapng -Y 'dns.qry.name' -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e dns.qry.name

tshark -r traffic.pcapng -Y 'http.request' -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e http.host \
  -e http.request.method -e http.request.uri
```

A DNS query does not mean the requester successfully connected to or exchanged data with the resolved host.

## 4. TCP streams and object reconstruction

```bash
tshark -r traffic.pcapng -Y 'tcp.stream == 3' -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.len

# Use Wireshark: Follow > TCP Stream on an actual stream ID.
# For HTTP objects: File > Export Objects > HTTP (only when relevant).
```

Check both directions of transfer, request/response status, payload sizes, content encoding, retransmissions and whether a reconstructed file hash is stable. For encrypted HTTPS, content may be unavailable unless decryption keys are explicitly provided by the exercise.

## 5. Workbench overview

```bash
python3 -m nexsec_dfir pcap-summary traffic.pcapng --max-packets 50000
```

The local `pcap-summary` is a **bounded metadata inventory**, not session reconstruction or protocol exploit analysis. It requires `tshark` and never submits the capture anywhere.

Official documentation: https://www.wireshark.org/docs/man-pages/tshark.html
