"""Bounded offline TShark evidence summary. Requires installed tshark."""
from __future__ import annotations

import collections
import csv
import shutil
import subprocess
from pathlib import Path
from .core import ForensicError

FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "frame.protocols", "tcp.stream", "dns.qry.name", "http.host", "http.request.uri"]


def pcap_summary(path: Path, *, max_packets: int = 50000, timeout_seconds: int = 180) -> dict:
    if not path.is_file():
        raise ForensicError("PCAP does not exist")
    if not 1 <= max_packets <= 500000:
        raise ForensicError("max_packets must be in range 1..500000")
    cmd = shutil.which("tshark")
    if not cmd:
        raise ForensicError("tshark unavailable; install it before offline analysis or use Wireshark manually")
    args = [cmd, "-r", str(path), "-c", str(max_packets), "-T", "fields"]
    for field in FIELDS:
        args.extend(["-e", field])
    args.extend(["-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"])
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds,
                                   check=False, errors="replace", env=None)
    except subprocess.TimeoutExpired as err:
        raise ForensicError(f"TShark exceeded {timeout_seconds}s; output not complete") from err
    if completed.returncode != 0:
        raise ForensicError(f"TShark exit {completed.returncode}: {completed.stderr[-600:]}")
    endpoints, protocols, dns, hosts, streams = (collections.Counter() for _ in range(5))
    n = 0
    for fields in csv.reader(completed.stdout.splitlines(), delimiter="\t", quotechar='"'):
        if len(fields) != len(FIELDS):
            continue
        n += 1
        number, epoch, src, dst, protos, stream, domain, host, _uri = fields
        for endpoint in (src, dst):
            if endpoint:
                endpoints[endpoint] += 1
        for proto in protos.split(":"):
            if proto:
                protocols[proto] += 1
        if domain:
            dns[domain] += 1
        if host:
            hosts[host] += 1
        if stream:
            streams[stream] += 1
    return {"capture": str(path), "frames_processed": n, "max_packets": max_packets,
            "possibly_truncated": n >= max_packets,
            "top_ip_endpoints": endpoints.most_common(30),
            "top_protocol_layers": protocols.most_common(30),
            "dns_query_names": dns.most_common(50),
            "http_host_headers": hosts.most_common(50),
            "tcp_stream_counts": streams.most_common(30),
            "note": "Counts are observed metadata, not proof of exfiltration, compromise or TCP transfer completion."
            }
