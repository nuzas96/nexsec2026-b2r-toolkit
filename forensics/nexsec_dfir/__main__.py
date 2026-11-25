"""CLI entry. Offline, no AI/network, no write to original evidence."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from . import __version__
from .archive import inventory_zip
from .csv_artifacts import inspect_csv
from .core import ForensicError, classify_file, create_case, sha256_file, verify_case, write_json
from .hunt import DEFAULT_PATTERN, hunt_strings
from .ledger import list_findings, record_finding, investigative_summary
from .pcap import pcap_summary
from .pcap import pcap_analyze
from .memory import analyze_memory
from .disk import analyze_disk
from .windows import analyze_windows
from .windows_exports import inspect_registry_export, reconstruct_scriptblocks
from .decoding import decode_value as decode_value_bytes, inspect_email_urls
from .chunks import reassemble_chunks
from .vhd import convert_vhd, DEFAULT_MAX_OUTPUT_BYTES
from .router import route
from .sqlite_artifacts import inspect_sqlite
from .timeline import build_timeline, normalize_time

RULES_FILE = Path(__file__).resolve().parent / "questions.json"


def print_json(data, output: str | None = None):
    if output:
        write_json(Path(output), data)
        print(f"Wrote report: {output}")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def doctor():
    tools = {
        "python": sys.version.split()[0],
        "tshark": shutil.which("tshark"),
        "vol": shutil.which("vol") or shutil.which("volatility3"),
        "mmls": shutil.which("mmls"), "fls": shutil.which("fls"),
        "icat": shutil.which("icat"), "ewfinfo": shutil.which("ewfinfo"),
        "exiftool": shutil.which("exiftool"), "binwalk": shutil.which("binwalk"),
        "7z": shutil.which("7z"), "yara": shutil.which("yara"),
        "sqlite3": shutil.which("sqlite3"), "bulk_extractor": shutil.which("bulk_extractor"),
        "EvtxECmd": shutil.which("EvtxECmd"), "PECmd": shutil.which("PECmd"),
        "MFTECmd": shutil.which("MFTECmd"), "LECmd": shutil.which("LECmd"),
        "RECmd": shutil.which("RECmd"), "AmcacheParser": shutil.which("AmcacheParser"),
        "mmls": shutil.which("mmls"), "fsstat": shutil.which("fsstat"),
        "ewfinfo": shutil.which("ewfinfo"),
        "qemu-img": shutil.which("qemu-img"),
    }
    return {"toolkit_version": __version__, "tools": tools,
            "note": "Missing tools mean their optional workflows are unavailable. No installations or network requests attempted."}


def validate_answer(kind: str, value: str, timestamp_encoding: str, assume_timezone: str | None):
    kind = kind.lower()
    found = False
    detail = ""
    if kind == "sha256":
        found = bool(re.fullmatch(r"[a-fA-F0-9]{64}", value))
    elif kind == "md5":
        found = bool(re.fullmatch(r"[a-fA-F0-9]{32}", value))
    elif kind == "ipv4":
        parts = value.split(".")
        found = len(parts) == 4 and all(p.isdigit() and str(int(p)) == p and 0 <= int(p) <= 255 for p in parts)
    elif kind == "sid":
        found = bool(re.fullmatch(r"S-1-(\d+-)+\d+", value))
    elif kind == "timestamp":
        try:
            normalized, basis, _zone = normalize_time(value, timestamp_encoding, assume_timezone)
            detail = f"Normalized UTC: {normalized}; basis: {basis}"
            found = True
        except (ValueError, OverflowError) as err:
            detail = str(err)
    elif kind == "hex":
        found = bool(re.fullmatch(r"(?:0x)?[a-fA-F0-9]+", value))
    else:
        raise ForensicError("Unknown answer type")
    return {"type": kind, "value": value, "format_valid": found,
            "detail": detail, "note": "Format/normalization check only; NOT validation that answer matches evidence or challenge ground truth."}


def parser_setup():
    ap = argparse.ArgumentParser(prog="python3 -m nexsec_dfir", description="Offline evidence-first CTF forensic workbench")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("case-init", help="hash and inventory read-only source evidence")
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--case", type=Path, required=True)
    p.add_argument("--max-files", type=int, default=10000)
    p = sub.add_parser("case-verify", help="compare source hashes with intake manifest")
    p.add_argument("--case", type=Path, required=True)
    p = sub.add_parser("classify", help="identify file signature and hash")
    p.add_argument("file", type=Path)
    p.add_argument("--output")
    p = sub.add_parser("zip-inventory", help="inspect ZIP entry metadata without extracting")
    p.add_argument("file", type=Path)
    p.add_argument("--output")
    p = sub.add_parser("sqlite-inspect", help="inspect SQLite using a throwaway working copy")
    p.add_argument("file", type=Path)
    p.add_argument("--table")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--output")
    p = sub.add_parser("csv-inspect", help="search/group external parser CSV exports (EVTX, Prefetch, MFT)")
    p.add_argument("file", type=Path)
    p.add_argument("--field", help="CSV header name to filter")
    p.add_argument("--equals", help="case-insensitive exact comparison")
    p.add_argument("--contains", help="case-insensitive substring search")
    p.add_argument("--select", help="comma-separated columns to show")
    p.add_argument("--group-field", help="count matching rows by one column")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--max-rows", type=int, default=250000)
    p.add_argument("--output")
    p = sub.add_parser("hunt", help="bounded interesting-string search with byte offsets")
    p.add_argument("file", type=Path)
    p.add_argument("--pattern", default=DEFAULT_PATTERN)
    p.add_argument("--min-length", type=int, default=5)
    p.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024)
    p.add_argument("--max-hits", type=int, default=1000)
    p.add_argument("--output")
    p = sub.add_parser("pcap-summary", help="offline tshark summary with capture + max packet cap")
    p.add_argument("file", type=Path)
    p.add_argument("--max-packets", type=int, default=50000)
    p.add_argument("--max-output-bytes", type=int, default=4000000)
    p.add_argument("--output")
    p = sub.add_parser("pcap-analyze", help="bounded TShark endpoint, DNS, HTTP, TCP, stream or object workflow")
    p.add_argument("file", type=Path)
    p.add_argument("--mode", choices=["endpoints", "dns", "http", "tcp", "stream", "objects"], required=True)
    p.add_argument("--max-packets", type=int, default=10000)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--max-output-bytes", type=int, default=4000000)
    p.add_argument("--stream-id", type=int)
    p.add_argument("--output-dir", type=Path)
    p.add_argument("--output")
    p = sub.add_parser("windows-artifact", help="parse EVTX, Prefetch, or MFT using installed Zimmerman tools (Windows only)")
    p.add_argument("file", type=Path)
    p.add_argument("--kind", choices=["evtx", "prefetch", "mft"], required=True)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--max-rows", type=int, default=100000)
    p.add_argument("--output")
    p = sub.add_parser("memory-analyze", help="run an allowlisted Volatility 3 plugin in offline mode")
    p.add_argument("file", type=Path)
    p.add_argument("--workflow", choices=["windows-processes", "windows-scan-processes", "windows-tree", "windows-command-line", "windows-network", "windows-modules", "windows-malfind", "windows-file-scan", "windows-dumpfiles", "windows-registry-hives", "windows-registry-key", "linux-processes", "linux-tree", "linux-command-line", "linux-network", "linux-modules", "linux-module-check"], required=True)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--max-output-bytes", type=int, default=4000000)
    p.add_argument("--registry-key", help="key path for windows-registry-key, e.g. Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    p.add_argument("--dump-dir", type=Path, help="new output directory required by windows-dumpfiles")
    p.add_argument("--max-dump-bytes", type=int, default=100000000)
    p.add_argument("--pid", type=int, help="limit windows-dumpfiles to one PID")
    p.add_argument("--dump-filter", help="Volatility windows.dumpfiles filename regex")
    p.add_argument("--output")
    p = sub.add_parser("disk-analyze", help="read-only TSK/libewf partition, filesystem, file-list, or extraction workflow")
    p.add_argument("file", type=Path)
    p.add_argument("--action", choices=["partitions", "filesystem", "files", "ewf-info", "extract"], required=True)
    p.add_argument("--offset", type=int, default=0, help="partition offset in sectors (not bytes)")
    p.add_argument("--sector-size", type=int, choices=[512, 1024, 2048, 4096])
    p.add_argument("--inode")
    p.add_argument("--filesystem", help="explicit TSK filesystem type, e.g. ntfs")
    p.add_argument("--extract-to", type=Path, help="new output path for --action extract")
    p.add_argument("--max-bytes", type=int, default=50_000_000)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--output")
    p = sub.add_parser("vhd-convert", help="validate and convert a VHD (QEMU vpc) to a new raw image")
    p.add_argument("file", type=Path)
    p.add_argument("--raw-output", type=Path, required=True)
    p.add_argument("--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    p.add_argument("--timeout", type=int, default=1800)
    p.add_argument("--output", help="new JSON report path")
    p = sub.add_parser("decode-value", help="offline Base64/XOR/text decoding; never executes decoded code")
    decode_input = p.add_mutually_exclusive_group(required=True)
    decode_input.add_argument("--value")
    decode_input.add_argument("--input-file", type=Path)
    p.add_argument("--base64", action="store_true", help="Base64 decode before XOR/text decoding")
    decode_key = p.add_mutually_exclusive_group()
    decode_key.add_argument("--xor-key-text")
    decode_key.add_argument("--xor-key-hex")
    p.add_argument("--text-encoding", choices=["utf-8", "utf-16le", "latin-1"], default="utf-8")
    p.add_argument("--decoded-file", type=Path, help="write decoded bytes to a new inert-data file")
    p.add_argument("--output", help="new JSON report path")
    p = sub.add_parser("email-urls", help="extract URLs and selected Base64 query values from an EML file")
    p.add_argument("file", type=Path)
    p.add_argument("--decode-param", help="name of a query parameter to Base64-decode")
    p.add_argument("--max-bytes", type=int, default=20_000_000)
    p.add_argument("--output")
    p = sub.add_parser("powershell-reconstruct", help="reassemble PowerShell Event 4104 script-block parser exports")
    p.add_argument("file", type=Path)
    p.add_argument("--id-field", default="ScriptBlockId")
    p.add_argument("--number-field", default="MessageNumber")
    p.add_argument("--total-field", default="MessageTotal")
    p.add_argument("--text-field", default="ScriptBlockText")
    p.add_argument("--event-field", default="EventId")
    p.add_argument("--event-id", default="4104")
    p.add_argument("--record-field", default="EventRecordId")
    p.add_argument("--payload-field", default="Payload", help="EvtxECmd JSON payload field; use empty string to disable")
    p.add_argument("--max-records", type=int, default=100000)
    p.add_argument("--write-scripts", type=Path, help="write complete reconstructed scripts to a new directory; scripts remain inert")
    p.add_argument("--output")
    p = sub.add_parser("registry-inspect", help="filter registry parser CSV/JSONL rows by key, name and data")
    p.add_argument("file", type=Path)
    p.add_argument("--key-field", default="KeyPath")
    p.add_argument("--name-field", default="ValueName")
    p.add_argument("--data-field", default="ValueData")
    p.add_argument("--key-contains")
    p.add_argument("--value-name")
    p.add_argument("--data-contains")
    p.add_argument("--max-records", type=int, default=100000)
    p.add_argument("--output")
    p = sub.add_parser("chunks-reassemble", help="validate and order Base64 chunks from JSON/HTTP parser exports")
    p.add_argument("file", type=Path)
    p.add_argument("--reassembled-output", type=Path, required=True)
    p.add_argument("--job")
    p.add_argument("--job-field", default="job")
    p.add_argument("--part-field", default="part")
    p.add_argument("--total-field", default="total")
    p.add_argument("--data-field", default="data")
    p.add_argument("--container-field")
    p.add_argument("--frame-field", default="frame.number")
    p.add_argument("--stream-field", default="tcp.stream")
    p.add_argument("--index-base", type=int, choices=[0, 1])
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--max-bytes", type=int, default=100000000)
    p.add_argument("--max-records", type=int, default=500000)
    p.add_argument("--output", help="new JSON report path")
    p = sub.add_parser("timeline-build", help="merge parser-exported CSV/JSONL files to UTC timeline")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-events", type=int, default=500000)
    p = sub.add_parser("route", help="rule-based likely artifact/tool suggestions for a CTF question")
    p.add_argument("question")
    p.add_argument("--output")
    p = sub.add_parser("finding-add", help="append sourced observation/interpretation to case ledger")
    p.add_argument("--case", type=Path, required=True)
    p.add_argument("--artifact", required=True, help="relative_path from case manifest")
    p.add_argument("--source-ref", required=True, help="e.g. EVTX record ID 123, CSV row 8, packet 42")
    p.add_argument("--observed", required=True)
    p.add_argument("--interpretation", required=True)
    p.add_argument("--confidence", required=True, choices=["confirmed-observation", "supported-inference", "hypothesis"])
    p.add_argument("--question", default="")
    p = sub.add_parser("finding-list", help="read existing case ledger")
    p.add_argument("--case", type=Path, required=True)
    p = sub.add_parser("investigative-summary", help="group sourced ledger entries and explicitly listed unknowns")
    p.add_argument("--case", type=Path, required=True)
    p.add_argument("--unknown", action="append", default=[], help="state an unresolved question; repeat as needed")
    p = sub.add_parser("answer-check", help="syntax and timestamp normalization only")
    p.add_argument("--type", required=True, choices=["sha256", "md5", "ipv4", "sid", "timestamp", "hex"])
    p.add_argument("--value", required=True)
    p.add_argument("--time-encoding", choices=["iso", "unix_s", "unix_ms", "filetime_100ns", "webkit_us"], default="iso")
    p.add_argument("--assume-timezone")
    sub.add_parser("doctor", help="show optional tool availability without installing anything")
    return ap


def main(argv=None):
    args = parser_setup().parse_args(argv)
    try:
        if args.command == "case-init":
            report = create_case(args.evidence, args.case, max_files=args.max_files)
        elif args.command == "case-verify":
            report = verify_case(args.case)
        elif args.command == "classify":
            report = {"file": str(args.file), "sha256": sha256_file(args.file), "classification": classify_file(args.file)}
        elif args.command == "zip-inventory":
            report = inventory_zip(args.file)
        elif args.command == "sqlite-inspect":
            report = inspect_sqlite(args.file, table=args.table, limit=args.limit)
        elif args.command == "csv-inspect":
            report = inspect_csv(args.file, field=args.field, equals=args.equals,
                                 contains=args.contains, select=args.select, group_field=args.group_field,
                                 limit=args.limit, max_rows=args.max_rows)
        elif args.command == "hunt":
            report = hunt_strings(args.file, pattern=args.pattern, min_length=args.min_length,
                                  max_bytes=args.max_bytes, max_hits=args.max_hits)
        elif args.command == "pcap-summary":
            report = pcap_summary(args.file, max_packets=args.max_packets, max_output=args.max_output_bytes)
        elif args.command == "pcap-analyze":
            report = pcap_analyze(args.file, mode=args.mode, max_packets=args.max_packets,
                                  timeout_seconds=args.timeout, stream_id=args.stream_id,
                                  output_dir=args.output_dir, max_output=args.max_output_bytes)
        elif args.command == "windows-artifact":
            report = analyze_windows(args.file, args.kind, timeout_seconds=args.timeout, max_rows=args.max_rows)
        elif args.command == "memory-analyze":
            report = analyze_memory(args.file, args.workflow, timeout_seconds=args.timeout,
                                    max_output=args.max_output_bytes, registry_key=args.registry_key,
                                    dump_dir=args.dump_dir, max_dump_bytes=args.max_dump_bytes,
                                    pid=args.pid, dump_filter=args.dump_filter)
        elif args.command == "disk-analyze":
            report = analyze_disk(args.file, args.action, offset=args.offset,
                                  sector_size=args.sector_size, inode=args.inode,
                                  filesystem=args.filesystem,
                                  output=args.extract_to, max_bytes=args.max_bytes,
                                  timeout_seconds=args.timeout)
        elif args.command == "vhd-convert":
            report = convert_vhd(args.file, args.raw_output, max_output_bytes=args.max_output_bytes,
                                  timeout_seconds=args.timeout)
        elif args.command == "decode-value":
            source_identity = None
            if args.input_file:
                if not args.input_file.is_file() or args.input_file.is_symlink() or args.input_file.stat().st_size > 20_000_000:
                    raise ForensicError("Input text file is missing, a symlink, or exceeds 20 MB")
                source_identity = {"source_artifact": str(args.input_file.resolve()), "source_sha256": sha256_file(args.input_file)}
                value = args.input_file.read_text(encoding="utf-8-sig")
                if sha256_file(args.input_file) != source_identity["source_sha256"]:
                    raise ForensicError("Decode input file changed while being read")
            else:
                value = args.value
            if args.xor_key_hex is not None:
                try:
                    key = bytes.fromhex(args.xor_key_hex)
                except ValueError as exc:
                    raise ForensicError("xor-key-hex must be even-length hexadecimal") from exc
            elif args.xor_key_text is not None:
                key = args.xor_key_text.encode("utf-8")
            else:
                key = None
            report, decoded = decode_value_bytes(value, from_base64=args.base64, xor_key=key,
                                                 text_encoding=args.text_encoding)
            if source_identity:
                report.update(source_identity)
            if args.decoded_file:
                target = args.decoded_file
                if target.exists() or target.is_symlink():
                    raise ForensicError("Decoded output exists; refusing overwrite")
                if args.input_file and args.input_file.resolve().parent in target.resolve().parents:
                    raise ForensicError("Decoded output must be outside the source directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as fp:
                    fp.write(decoded)
                report["decoded_file"] = str(target.resolve())
        elif args.command == "email-urls":
            report = inspect_email_urls(args.file, decode_param=args.decode_param, max_bytes=args.max_bytes)
        elif args.command == "powershell-reconstruct":
            report = reconstruct_scriptblocks(args.file, id_field=args.id_field,
                number_field=args.number_field, total_field=args.total_field, text_field=args.text_field,
                event_field=args.event_field, event_id=args.event_id, record_field=args.record_field,
                payload_field=args.payload_field or None,
                max_records=args.max_records, write_scripts=args.write_scripts)
        elif args.command == "registry-inspect":
            report = inspect_registry_export(args.file, key_field=args.key_field,
                name_field=args.name_field, data_field=args.data_field,
                key_contains=args.key_contains, value_name=args.value_name,
                data_contains=args.data_contains, max_records=args.max_records)
        elif args.command == "chunks-reassemble":
            report = reassemble_chunks(args.file, args.reassembled_output, job=args.job,
                job_field=args.job_field, part_field=args.part_field, total_field=args.total_field,
                data_field=args.data_field, container_field=args.container_field,
                frame_field=args.frame_field, stream_field=args.stream_field,
                index_base=args.index_base, expected_size=args.expected_size,
                expected_sha256=args.expected_sha256, max_bytes=args.max_bytes,
                max_records=args.max_records)
        elif args.command == "timeline-build":
            report = build_timeline(args.manifest, args.output, max_events=args.max_events)
        elif args.command == "route":
            report = route(args.question, RULES_FILE)
        elif args.command == "finding-add":
            report = record_finding(args.case, artifact=args.artifact, source_ref=args.source_ref,
                                    observed=args.observed, interpretation=args.interpretation,
                                    confidence=args.confidence, question=args.question)
        elif args.command == "finding-list":
            report = list_findings(args.case)
        elif args.command == "investigative-summary":
            report = investigative_summary(args.case, args.unknown)
        elif args.command == "answer-check":
            report = validate_answer(args.type, args.value, args.time_encoding, args.assume_timezone)
        else:
            report = doctor()
        print_json(report, None if args.command == "timeline-build" else getattr(args, "output", None))
        if args.command == "case-verify" and not report["passed"]:
            return 1
        if args.command == "answer-check" and not report["format_valid"]:
            return 1
        return 0
    except (ForensicError, FileNotFoundError, PermissionError, OSError, ValueError, json.JSONDecodeError) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
