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
from .ledger import list_findings, record_finding
from .pcap import pcap_summary
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
            normalized, basis = normalize_time(value, timestamp_encoding, assume_timezone)
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
    p.add_argument("--output")
    p = sub.add_parser("timeline-build", help="merge parser-exported CSV/JSONL files to UTC timeline")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
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
            report = pcap_summary(args.file, max_packets=args.max_packets)
        elif args.command == "timeline-build":
            report = build_timeline(args.manifest, args.output)
        elif args.command == "route":
            report = route(args.question, RULES_FILE)
        elif args.command == "finding-add":
            report = record_finding(args.case, artifact=args.artifact, source_ref=args.source_ref,
                                    observed=args.observed, interpretation=args.interpretation,
                                    confidence=args.confidence, question=args.question)
        elif args.command == "finding-list":
            report = list_findings(args.case)
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
