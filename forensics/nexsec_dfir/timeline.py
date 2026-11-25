"""Deterministic timeline merger from existing CSV/JSONL parser exports.

No raw Windows/MFT/EVTX decoding is claimed here: supply trusted exports first.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from .core import ForensicError, sha256_file, utc_now

UTC = timezone.utc
START_1601 = datetime(1601, 1, 1, tzinfo=UTC)
START_1970 = datetime(1970, 1, 1, tzinfo=UTC)


def parse_zone(label: str | None):
    if not label:
        raise ValueError("Naive timestamp lacks timezone; specify assume_timezone")
    if label.upper() in {"UTC", "Z"}:
        return UTC
    try:
        return ZoneInfo(label)
    except (ZoneInfoNotFoundError, KeyError):
        pass
    if len(label) == 6 and label[0] in "+-" and label[3] == ":":
        try:
            h, m = int(label[1:3]), int(label[4:6])
            if h > 23 or m > 59:
                raise ValueError("invalid offset")
            return timezone(timedelta(minutes=(h * 60 + m) * (1 if label[0] == "+" else -1)))
        except ValueError:
            pass
    raise ValueError(f"Unknown timezone: {label}")


def normalize_time(value, fmt: str, assumed_timezone: str | None) -> tuple[str, str, str]:
    """Return ISO UTC and conversion annotation. Ambiguous dates are rejected."""
    raw = str(value).strip()
    if not raw:
        raise ValueError("Empty timestamp")
    if fmt == "iso":
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as err:
            raise ValueError("Not an unambiguous ISO-8601 timestamp") from err
        if dt.tzinfo is None:
            zone = parse_zone(assumed_timezone)
            if isinstance(zone, ZoneInfo):
                first = dt.replace(tzinfo=zone, fold=0)
                second = dt.replace(tzinfo=zone, fold=1)
                roundtrip_first = first.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
                roundtrip_second = second.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
                if dt not in (roundtrip_first, roundtrip_second):
                    raise ValueError("Nonexistent local timestamp during timezone transition")
                if first.utcoffset() != second.utcoffset():
                    raise ValueError("Ambiguous local timestamp during timezone transition; provide explicit UTC offset")
            dt = dt.replace(tzinfo=zone)
            basis = f"assumed timezone {assumed_timezone}"
            original_timezone = assumed_timezone
        else:
            basis = "timezone explicitly present in timestamp"
            original_timezone = dt.tzname() or str(dt.utcoffset())
    elif fmt in {"unix_s", "unix_ms", "filetime_100ns", "webkit_us"}:
        try:
            n = int(raw)
        except ValueError as err:
            raise ValueError(f"{fmt} requires an integer") from err
        if fmt == "unix_s":
            dt = START_1970 + timedelta(seconds=n)
        elif fmt == "unix_ms":
            dt = START_1970 + timedelta(milliseconds=n)
        elif fmt == "filetime_100ns":
            dt = START_1601 + timedelta(microseconds=n // 10)
        else:
            dt = START_1601 + timedelta(microseconds=n)
        basis = fmt + (" (100ns truncated to microsecond)" if fmt == "filetime_100ns" else "")
        original_timezone = "UTC (epoch-based encoding)"
    else:
        raise ValueError(f"Unsupported time encoding: {fmt}")
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z"), basis, original_timezone


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    # Defang user-controlled formulas when CSV is opened in spreadsheet software.
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def build_timeline(config_path: Path, output: Path, *, max_events: int = 500000) -> dict:
    """A JSON manifest lists parser exports and their time column semantics."""
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("sources"), list) or not config["sources"]:
        raise ForensicError("Config must contain a non-empty sources array")
    if output.exists() or output.with_suffix(output.suffix + ".errors.jsonl").exists():
        raise ForensicError("Refusing overwrite of existing timeline or errors file")
    if not 1 <= max_events <= 2_000_000:
        raise ForensicError("max-events must be in range 1..2000000")
    events, errors = [], []
    for spec in config["sources"]:
        for required in ("path", "format", "time_field", "event_field", "time_encoding"):
            if required not in spec:
                raise ForensicError(f"Source config is missing {required}")
        p = Path(spec["path"])
        if not p.is_absolute():
            p = config_path.parent / p
        p = p.resolve()
        if not p.is_file():
            raise ForensicError(f"Source export not found: {p}")
        if output.resolve() == p:
            raise ForensicError("Output cannot replace a source export")
        source_hash = sha256_file(p)
        if spec["format"] not in ("csv", "jsonl"):
            raise ForensicError(f"Expected csv or jsonl, got {spec['format']}")
        with p.open("r", encoding="utf-8-sig", newline="") as fp:
            if spec["format"] == "csv":
                iterable = enumerate(csv.DictReader(fp), start=2)
            else:
                def parse_lines():
                    for idx, line in enumerate(fp, start=1):
                        if not line.strip():
                            continue
                        try:
                            result = json.loads(line)
                        except ValueError as err:
                            errors.append({"source": str(p), "row": idx, "reason": f"Bad JSON: {err}"})
                            continue
                        if not isinstance(result, dict):
                            errors.append({"source": str(p), "row": idx, "reason": "JSONL row not an object"})
                            continue
                        yield idx, result
                iterable = parse_lines()
            for row_num, row in iterable:
                try:
                    t = row.get(spec["time_field"])
                    normalized, basis, original_timezone = normalize_time(t, spec["time_encoding"], spec.get("assume_timezone"))
                    ev = row.get(spec["event_field"], "")
                    ref = row.get(spec.get("reference_field", ""), "")
                    events.append({"timestamp_utc": normalized,
                                   "timestamp_raw": str(t), "time_basis": basis,
                                   "original_timezone": original_timezone,
                                   "source": spec.get("name", p.name),
                                   "source_file": str(p), "source_row": row_num,
                                   "source_sha256": source_hash,
                                   "artifact_type": spec.get("artifact_type", "unknown"),
                                   "event": str(ev), "source_reference": str(ref or ""),
                                   "association_key": str(row.get(spec.get("association_field", ""), "") or ""),
                                   "duplicate_of_prior": ""})
                    if len(events) > max_events:
                        raise ForensicError(f"More than max-events={max_events}; timeline stopped rather than silently truncate")
                except (ValueError, TypeError, OverflowError, OSError) as err:
                    errors.append({"source": str(p), "row": row_num, "reason": str(err),
                                   "timestamp_raw": str(row.get(spec["time_field"]))})
        if sha256_file(p) != source_hash:
            raise ForensicError(f"Timeline source export changed while being read: {p}")
    events.sort(key=lambda e: (e["timestamp_utc"], e["source_file"], e["source_row"]))
    seen: set[tuple[str, str, str]] = set()
    for ev in events:
        identity = (ev["timestamp_utc"], ev["source"], ev["event"])
        if identity in seen:
            ev["duplicate_of_prior"] = "REVIEW"
        else:
            seen.add(identity)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ("timestamp_utc", "timestamp_raw", "original_timezone", "time_basis", "source", "source_file",
              "source_sha256", "source_row", "artifact_type", "event", "source_reference", "association_key", "duplicate_of_prior")
    if output.suffix.lower() == ".jsonl":
        with output.open("x", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    else:
        with output.open("x", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ev in events:
                writer.writerow({key: csv_safe(val) if isinstance(val, str) else val for key, val in ev.items()})
    errorfile = output.with_suffix(output.suffix + ".errors.jsonl")
    with errorfile.open("x", encoding="utf-8") as f:
        for error in errors:
            f.write(json.dumps(error, ensure_ascii=False) + "\n")
    return {"created_at_utc": utc_now(), "timeline_path": str(output),
            "error_path": str(errorfile), "events": len(events),
            "unparsed_rows": len(errors), "duplicates_for_review": sum(bool(x["duplicate_of_prior"]) for x in events),
            "note": "Records are sorted chronologically and retain raw timestamps, timezone basis, source hashes and record references. Matching association_key values group records for review; association does not assert causation."
            }
