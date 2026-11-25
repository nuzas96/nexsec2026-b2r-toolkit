"""SQLite metadata and bounded table reads via a temporary working COPY."""
from __future__ import annotations

import base64
import shutil
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
from .core import ForensicError


def _json_value(obj):
    if isinstance(obj, bytes):
        return {"base64": base64.b64encode(obj).decode("ascii"), "type": "blob"}
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def inspect_sqlite(db_path: Path, *, table: str | None = None, limit: int = 25) -> dict:
    if limit < 0 or limit > 500:
        raise ForensicError("Row limit must be between 0 and 500")
    if not db_path.is_file():
        raise ForensicError(f"SQLite file not found: {db_path}")
    accompanying = [p for p in (Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")) if p.exists()]
    with TemporaryDirectory(prefix="nexsec-sqlite-working-copy-") as tmp:
        work_db = Path(tmp) / "working.sqlite"
        shutil.copy2(db_path, work_db)
        for companion in accompanying:
            shutil.copy2(companion, Path(str(work_db) + companion.name[len(db_path.name):]))
        try:
            conn = sqlite3.connect(f"file:{work_db}?mode=ro", uri=True, timeout=3)
            conn.execute("PRAGMA query_only=ON")
            schema = conn.execute("SELECT type, name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name").fetchall()
            tables = []
            for obj_type, name in schema:
                safe = '"' + name.replace('"', '""') + '"'
                columns = [{"name": x[1], "type": x[2], "pk": bool(x[5])}
                           for x in conn.execute(f"PRAGMA table_info({safe})")]
                tables.append({"name": name, "kind": obj_type, "columns": columns})
            result = {"path": str(db_path), "tables": tables, "sample_rows": [],
                      "wal_present": any(p.name.endswith("-wal") for p in accompanying),
                      "note": "Inspected a temporary copy; WAL copied if available; concurrent source changes may make snapshots inconsistent."}
            if table is not None:
                if table not in [x["name"] for x in tables]:
                    raise ForensicError(f"Table/view does not exist: {table}")
                safe = '"' + table.replace('"', '""') + '"'
                conn.row_factory = sqlite3.Row
                rows = conn.execute(f"SELECT * FROM {safe} LIMIT ?", (limit,)).fetchall()
                result["sample_rows"] = [{k: _json_value(row[k]) for k in row.keys()} for row in rows]
                result["sample_note"] = f"At most {limit} unsorted rows; not an exhaustive analysis"
            conn.close()
            return result
        except sqlite3.DatabaseError as err:
            raise ForensicError(f"SQLite parsing failed: {err}") from err
