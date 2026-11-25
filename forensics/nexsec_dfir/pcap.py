"""Bounded offline TShark evidence summary. Requires installed tshark."""
from __future__ import annotations

import collections
import csv
import hashlib
import shutil
import subprocess
from pathlib import Path
from .core import ForensicError
from .external import evidence_identity, run_bounded, verify_source_unchanged

FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "frame.protocols", "tcp.stream", "dns.qry.name", "http.host", "http.request.uri"]


def pcap_summary(path: Path, *, max_packets: int = 50000, timeout_seconds: int = 180,
                 max_output: int = 4_000_000) -> dict:
    if not path.is_file():
        raise ForensicError("PCAP does not exist")
    identity = evidence_identity(path)
    if not 1 <= max_packets <= 500000:
        raise ForensicError("max_packets must be in range 1..500000")
    if timeout_seconds <= 0 or max_output < 1024:
        raise ForensicError("timeout must be positive and max_output must be at least 1024 bytes")
    cmd = shutil.which("tshark")
    if not cmd:
        raise ForensicError("tshark unavailable; install it before offline analysis or use Wireshark manually")
    args = [cmd, "-r", str(path), "-c", str(max_packets), "-T", "fields"]
    for field in FIELDS:
        args.extend(["-e", field])
    args.extend(["-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"])
    try:
        completed, output_truncated = run_bounded(args, timeout=timeout_seconds, max_output=max_output)
    except ForensicError as err:
        verify_source_unchanged(path, identity)
        if "timed out" not in str(err):
            raise
        raise ForensicError(f"TShark exceeded {timeout_seconds}s; output not complete") from err
    if completed.returncode != 0 and not output_truncated:
        verify_source_unchanged(path, identity)
        raise ForensicError(f"TShark exit {completed.returncode}: {completed.stderr[-600:].decode('utf-8','replace')}")
    endpoints, protocols, dns, hosts, streams = (collections.Counter() for _ in range(5))
    n = 0
    for fields in csv.reader(completed.stdout.decode("utf-8", "replace").splitlines(), delimiter="\t", quotechar='"'):
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
    verify_source_unchanged(path, identity)
    return {**identity, "frames_processed": n, "max_packets": max_packets,
            "possibly_truncated": n >= max_packets or output_truncated,
            "output_truncated": output_truncated,
            "top_ip_endpoints": endpoints.most_common(30),
            "top_protocol_layers": protocols.most_common(30),
            "dns_query_names": dns.most_common(50),
            "http_host_headers": hosts.most_common(50),
            "tcp_stream_counts": streams.most_common(30),
            "note": "Counts are observed metadata, not proof of exfiltration, compromise or TCP transfer completion."
            }


PCAP_MODES = {
    "endpoints": ("frame.number", "ip.src", "ip.dst", "frame.protocols", "tcp.stream"),
    "dns": ("frame.number", "frame.time_epoch", "ip.src", "ip.dst", "dns.qry.name", "dns.a", "dns.resp.name", "dns.flags.rcode"),
    "http": ("frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream", "http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_length"),
    "tcp": ("frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.flags"),
}


def pcap_analyze(path: Path, *, mode: str, max_packets: int = 10000,
                 timeout_seconds: int = 180, stream_id: int | None = None,
                 output_dir: Path | None = None, max_output: int = 4_000_000) -> dict:
    """Extract bounded frame records or a TCP stream view using local TShark."""
    if mode not in {*PCAP_MODES, "stream", "objects"}:
        raise ForensicError("mode must be endpoints, dns, http, tcp, stream, or objects")
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"PCAP does not exist or is a symlink: {path}")
    identity = evidence_identity(path)
    if not 1 <= max_packets <= 100000:
        raise ForensicError("max_packets must be in range 1..100000")
    if timeout_seconds <= 0 or max_output < 1024:
        raise ForensicError("timeout must be positive and max_output must be at least 1024 bytes")
    cmd = shutil.which("tshark")
    if not cmd:
        raise ForensicError("tshark unavailable; install it before offline analysis")
    base = [cmd, "-r", str(path), "-c", str(max_packets)]
    if mode in PCAP_MODES:
        fields = PCAP_MODES[mode]
        args = base + ["-T", "fields"]
        for field in fields:
            args.extend(["-e", field])
        args.extend(["-E", "header=n", "-E", "separator=/t", "-E", "quote=d"])
        filters = {"dns": "dns", "http": "http", "tcp": "tcp", "endpoints": "ip"}
        args.extend(["-Y", filters[mode]])
        try:
            result, output_truncated = run_bounded(args, timeout=timeout_seconds, max_output=max_output)
        except ForensicError as exc:
            verify_source_unchanged(path, identity)
            if "timed out" not in str(exc):
                raise
            raise ForensicError(f"TShark timed out after {timeout_seconds}s; results incomplete") from exc
        if result.returncode and not output_truncated:
            verify_source_unchanged(path, identity)
            raise ForensicError(f"TShark exited {result.returncode}: {result.stderr[-1000:].decode('utf-8','replace')}")
        text = result.stdout.decode("utf-8", "replace")
        rows = []
        for row_no, values in enumerate(csv.reader(text.splitlines(), delimiter="\t", quotechar='"'), 1):
            if len(values) != len(fields):
                continue
            rows.append({field: value for field, value in zip(fields, values)})
        verify_source_unchanged(path, identity)
        return {**identity, "mode": mode, "records": rows,
                "records_returned": len(rows), "max_packets": max_packets,
                "possibly_truncated": len(rows) >= max_packets or output_truncated,
                "output_truncated": output_truncated,
                "tool": "tshark", "note": "Frame observations retain frame.number where selected; DNS/connection observations alone do not establish successful transfer or exfiltration."}
    if mode == "stream":
        if stream_id is None or stream_id < 0:
            raise ForensicError("stream mode requires --stream-id with a non-negative stream number")
        args = base + ["-q", "-z", f"follow,tcp,raw,{stream_id}"]
        try:
            result, output_truncated = run_bounded(args, timeout=timeout_seconds, max_output=max_output)
        except ForensicError as exc:
            verify_source_unchanged(path, identity)
            if "timed out" not in str(exc):
                raise
            raise ForensicError(f"TShark timed out after {timeout_seconds}s; stream is incomplete") from exc
        if result.returncode and not output_truncated:
            verify_source_unchanged(path, identity)
            raise ForensicError(f"TShark exited {result.returncode}: {result.stderr[-1000:].decode('utf-8','replace')}")
        output = result.stdout.decode("utf-8", "replace")
        verify_source_unchanged(path, identity)
        return {**identity, "mode": mode, "stream_id": stream_id,
                "stream_output": output, "output_truncated": output_truncated,
                "tool": "tshark", "note": "Raw follow-stream view is tool-formatted; inspect both directions and protocol semantics before inferring transfer."}
    if output_dir is None:
        raise ForensicError("objects mode requires --output-dir for isolated extracted objects")
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise ForensicError(f"Refusing to reuse existing extraction directory: {output_dir}")
    resolved = output_dir.resolve()
    if resolved == path.resolve() or path.resolve() in resolved.parents:
        raise ForensicError("Object output directory must be outside the evidence file/tree")
    if path.resolve().parent in resolved.parents:
        raise ForensicError("Object output directory must be outside the source evidence directory")
    output_dir.mkdir(parents=True, mode=0o700)
    args = [cmd, "-r", str(path), "-c", str(max_packets), "--export-objects", f"http,{output_dir}"]
    try:
        result, output_truncated = run_bounded(args, timeout=timeout_seconds, max_output=max_output)
    except ForensicError as exc:
        verify_source_unchanged(path, identity)
        if "timed out" not in str(exc):
            raise
        raise ForensicError(f"TShark timed out after {timeout_seconds}s; object export may be incomplete") from exc
    if result.returncode and not output_truncated:
        verify_source_unchanged(path, identity)
        raise ForensicError(f"TShark exited {result.returncode}: {result.stderr[-1000:].decode('utf-8','replace')}")
    objects = []
    for item in sorted(output_dir.iterdir()):
        if not item.is_file() or item.is_symlink():
            continue
        digest = hashlib.sha256()
        with item.open("rb") as fp:
            for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                digest.update(chunk)
        objects.append({"path": str(item), "size_bytes": item.stat().st_size, "sha256": digest.hexdigest()})
    verify_source_unchanged(path, identity)
    return {**identity, "mode": mode, "objects": objects,
            "objects_returned": len(objects), "max_packets": max_packets,
            "output_truncated": output_truncated,
            "tool": "tshark", "note": "HTTP object extraction is bounded by packet count; extracted objects are untrusted and were not opened or executed."}
