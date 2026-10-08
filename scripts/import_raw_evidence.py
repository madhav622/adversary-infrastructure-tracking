from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
DB_FILE = ROOT / "database" / "intel.db"
LOG_FILE = ROOT / "logs" / "import_raw_evidence.log"
ALLOWED = ("S001", "S002", "S003", "S004")


def find_evidence_files(raw_dir: Path) -> list[tuple[str, Path]]:
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"Raw evidence folder not found: {raw_dir}")

    found = []
    for path in sorted(raw_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() != ".json":
            continue
        if "manifest" in path.stem.casefold():
            continue

        for seed_id in ALLOWED:
            if path.name.upper().startswith(seed_id + "_"):
                found.append((seed_id, path))
                break
    return found


def get_source(filename: str) -> str:
    name = filename.casefold()
    if "virustotal" in name:
        return "VirusTotal"
    if "shodan" in name:
        return "Shodan"
    if "threatfox" in name:
        return "ThreatFox"
    return "manual-collected"


def get_observed_at(payload) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("observed_at_utc", "observed_at", "scan_time_utc"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def get_reference(payload) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("source_reference", "reference_url", "permalink", "url"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def import_evidence(raw_dir: Path, db_path: Path) -> tuple[int, int, dict]:
    files = find_evidence_files(raw_dir)
    if not files:
        raise ValueError("No S001-S004 raw JSON evidence files found")

    records = []
    for seed_id, path in files:
        raw_bytes = path.read_bytes()
        try:
            payload = json.loads(raw_bytes.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Invalid JSON evidence file {path.name}: {exc}"
            ) from exc

        relative_path = f"data/raw/{path.name}"
        digest = hashlib.sha256(raw_bytes).hexdigest()
        evidence_id = "evidence--" + hashlib.sha256(
            relative_path.encode("utf-8")
        ).hexdigest()

        evidence_type = path.stem[len(seed_id) + 1:]
        evidence_type = re.sub(r"_20\d{6}$", "", evidence_type)
        evidence_type = evidence_type or "raw-json"

        details = json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )

        records.append((
            evidence_id,
            seed_id,
            get_source(path.name),
            evidence_type,
            get_reference(payload),
            relative_path,
            digest,
            get_observed_at(payload),
            details,
        ))

    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                evidence_id TEXT PRIMARY KEY,
                seed_id TEXT
                    CHECK(seed_id IS NULL OR seed_id IN
                    ('S001','S002','S003','S004')),
                source_name TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                source_reference TEXT,
                raw_file_path TEXT,
                raw_sha256 TEXT,
                observed_at_utc TEXT,
                details_json TEXT NOT NULL
            )
        """)

        inserted = 0
        counts = {seed: 0 for seed in ALLOWED}

        with conn:
            for record in records:
                (
                    evidence_id, seed_id, source, evidence_type,
                    reference, file_path, digest, observed, details
                ) = record

                existing = conn.execute(
                    """SELECT seed_id, source_name, evidence_type,
                              source_reference, raw_file_path, raw_sha256,
                              observed_at_utc, details_json
                       FROM evidence_records WHERE evidence_id = ?""",
                    (evidence_id,),
                ).fetchone()

                expected = (
                    seed_id, source, evidence_type, reference,
                    file_path, digest, observed, details
                )

                if existing is not None:
                    if tuple(existing) != expected:
                        raise ValueError(
                            f"Evidence changed since ingestion: {file_path}. "
                            "Preserve the original and add a new file."
                        )
                    counts[seed_id] += 1
                    continue

                conn.execute(
                    """INSERT INTO evidence_records
                       (evidence_id, seed_id, source_name, evidence_type,
                        source_reference, raw_file_path, raw_sha256,
                        observed_at_utc, details_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    record,
                )
                inserted += 1
                counts[seed_id] += 1

        total = conn.execute(
            "SELECT COUNT(*) FROM evidence_records"
        ).fetchone()[0]

    return inserted, total, counts


def main() -> int:
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        inserted, total, counts = import_evidence(RAW_DIR, DB_FILE)
        logging.info(
            "Raw evidence imported: inserted=%d total=%d",
            inserted, total,
        )
        print(f"Database: {DB_FILE}")
        print(f"New evidence records: {inserted}")
        print(f"Total evidence records: {total}")
        for seed_id, count in counts.items():
            print(f"{seed_id} evidence files: {count}")
        print("Scope: S001-S004; S005 and manifest excluded")
        return 0
    except Exception as exc:
        logging.exception("Raw evidence import failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
