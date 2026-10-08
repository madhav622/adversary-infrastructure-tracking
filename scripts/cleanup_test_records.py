from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "database" / "intel.db"
DEFAULT_REVIEW = ROOT / "data" / "review" / "edge_review_decisions.json"
DEFAULT_ARCHIVE = ROOT / "data" / "archive" / "test_record_cleanup"

KNOWN_TEST_REASONS = {
    "manual triage testing completed",
    "alert reviewed and triaged for testing",
    "review reason",
    "pending manual verification. testing analyst decision persistence.",
}


def _normalize_reason(value) -> str:
    return " ".join(str(value or "").casefold().split())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_review(path: Path):
    if not path.exists():
        return None, None
    raw = path.read_bytes()
    parsed = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(parsed, dict):
        raise ValueError(f"Review file must contain a JSON object: {path}")
    return raw, parsed


def _atomic_write(path: Path, payload: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def cleanup_test_records(
    database: Path = DEFAULT_DB,
    review_file: Path = DEFAULT_REVIEW,
    archive_dir: Path = DEFAULT_ARCHIVE,
) -> dict:
    """Archive exact known test records, then remove them from working stores."""
    database = Path(database)
    review_file = Path(review_file)
    archive_dir = Path(archive_dir)
    if not database.is_file():
        raise FileNotFoundError(f"Database not found: {database}")

    review_original, review = _read_review(review_file)
    review_cleaned = None
    removed_decisions = {}
    removed_review_history = []
    if review is not None:
        decisions = review.get("decisions", {})
        if isinstance(decisions, dict):
            for edge_id, decision in list(decisions.items()):
                if isinstance(decision, dict) and _normalize_reason(decision.get("reason")) in KNOWN_TEST_REASONS:
                    removed_decisions[edge_id] = decisions.pop(edge_id)
        history = review.get("history", [])
        if isinstance(history, list):
            retained = []
            for item in history:
                if isinstance(item, dict) and _normalize_reason(item.get("reason")) in KNOWN_TEST_REASONS:
                    removed_review_history.append(item)
                else:
                    retained.append(item)
            review["history"] = retained
        if removed_decisions or removed_review_history:
            review["updated_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            review_cleaned = (json.dumps(review, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    with sqlite3.connect(str(database), timeout=30) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(alert_triage_history)")]
        db_rows = []
        if columns and "reason" in columns:
            matches = conn.execute(
                "SELECT * FROM alert_triage_history ORDER BY rowid"
            ).fetchall()
            for row in matches:
                record = dict(zip(columns, row))
                if _normalize_reason(record.get("reason")) in KNOWN_TEST_REASONS:
                    db_rows.append(record)

    if not db_rows and not removed_decisions and not removed_review_history:
        return {"changed": False, "database_rows": 0, "review_decisions": 0, "review_history": 0, "archive": None}

    archive_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_path = archive_dir / f"cleanup_{timestamp}.json"
    suffix = 1
    while archive_path.exists():
        archive_path = archive_dir / f"cleanup_{timestamp}_{suffix}.json"
        suffix += 1

    database_backup_path = archive_path.with_suffix(".database.sqlite3")
    with sqlite3.connect(str(database), timeout=30) as source_conn:
        with sqlite3.connect(str(database_backup_path), timeout=30) as backup_conn:
            source_conn.backup(backup_conn)

    archive = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "database_backup_file": database_backup_path.name,
        "database_backup_sha256": _sha256(database_backup_path.read_bytes()),
        "database_rows": db_rows,
        "review_decisions": removed_decisions,
        "review_history": removed_review_history,
        "review_original_base64": base64.b64encode(review_original).decode("ascii") if review_original is not None and review_cleaned is not None else None,
        "review_original_sha256": _sha256(review_original) if review_original is not None and review_cleaned is not None else None,
        "review_cleaned_sha256": _sha256(review_cleaned) if review_cleaned is not None else None,
    }
    archive_bytes = (json.dumps(archive, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write(archive_path, archive_bytes)

    with sqlite3.connect(str(database), timeout=30) as conn:
        if db_rows:
            if not columns:
                raise ValueError("Archive contains triage rows but alert_triage_history table is missing")
            placeholders = ",".join("?" for _ in columns)
            conn.executemany(
                f"DELETE FROM alert_triage_history WHERE history_id=?",
                [(row["history_id"],) for row in db_rows],
            )
        conn.commit()

    if review_cleaned is not None:
        _atomic_write(review_file, review_cleaned)

    return {
        "changed": True,
        "database_rows": len(db_rows),
        "review_decisions": len(removed_decisions),
        "review_history": len(removed_review_history),
        "archive": str(archive_path),
    }


def restore_test_records(
    archive_file: Path,
    database: Path = DEFAULT_DB,
    review_file: Path = DEFAULT_REVIEW,
) -> dict:
    """Restore archived records; refuse to overwrite post-cleanup review edits."""
    archive_file = Path(archive_file)
    database = Path(database)
    review_file = Path(review_file)
    archive = json.loads(archive_file.read_text(encoding="utf-8"))
    if archive.get("schema_version") != 1:
        raise ValueError("Unsupported cleanup archive schema")

    original_b64 = archive.get("review_original_base64")
    if original_b64 is not None:
        if not review_file.is_file():
            raise ValueError("Review file missing; refusing unsafe restore")
        current_hash = _sha256(review_file.read_bytes())
        if current_hash != archive.get("review_cleaned_sha256"):
            raise ValueError("Review file changed after cleanup; refusing to overwrite analyst edits")

    rows = archive.get("database_rows", [])
    with sqlite3.connect(str(database), timeout=30) as conn:
        if rows:
            columns = list(rows[0].keys())
            placeholders = ",".join("?" for _ in columns)
            col_sql = ",".join('"' + name.replace('"', '""') + '"' for name in columns)
            conn.executemany(
                f"INSERT OR IGNORE INTO alert_triage_history ({col_sql}) VALUES ({placeholders})",
                [tuple(row[name] for name in columns) for row in rows],
            )
        conn.commit()

    if original_b64 is not None:
        original_bytes = base64.b64decode(original_b64, validate=True)
        if _sha256(original_bytes) != archive.get("review_original_sha256"):
            raise ValueError("Cleanup archive review-file checksum mismatch")
        _atomic_write(review_file, original_bytes)

    return {
        "restored_database_rows": len(rows),
        "restored_review_decisions": len(archive.get("review_decisions", {})),
        "restored_review_history": len(archive.get("review_history", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument("--review-file", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--archive-dir", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--restore", type=Path, help="Restore from a cleanup archive")
    args = parser.parse_args()
    try:
        if args.restore:
            result = restore_test_records(args.restore, args.database, args.review_file)
            print("Cleanup records restored:", result)
        else:
            result = cleanup_test_records(args.database, args.review_file, args.archive_dir)
            print("Cleanup result:", result)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
