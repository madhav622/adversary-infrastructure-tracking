from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_FILE = ROOT / "exports" / "seeds_s001_s004_stix21.json"
DB_FILE = ROOT / "database" / "intel.db"
LOG_FILE = ROOT / "logs" / "load_stix_db.log"

ALLOWED_SEEDS = {"S001", "S002", "S003", "S004"}


def extract_seed_id(obj: dict) -> str | None:
    if obj.get("type") != "indicator":
        return None

    refs = obj.get("external_references", [])
    ids = [
        str(ref["external_id"]).strip().upper()
        for ref in refs
        if isinstance(ref, dict) and ref.get("external_id")
    ]
    seed_ids = [sid for sid in ids if sid.startswith("S")]

    if len(seed_ids) != 1:
        raise ValueError(
            f"Indicator {obj.get('id')} must have exactly one seed ID"
        )

    seed_id = seed_ids[0]
    if seed_id not in ALLOWED_SEEDS:
        raise ValueError(f"Out-of-scope seed rejected: {seed_id}")

    return seed_id


def load_bundle(bundle_path: Path, db_path: Path) -> tuple[int, int]:
    if not bundle_path.is_file():
        raise FileNotFoundError(f"STIX bundle not found: {bundle_path}")

    bundle = json.loads(bundle_path.read_text(encoding="utf-8-sig"))
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("Input is not a STIX bundle")

    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("STIX bundle contains no objects")

    records = []
    found_seeds = set()
    seen_ids = set()

    for obj in objects:
        if not isinstance(obj, dict):
            raise ValueError("STIX bundle contains a non-object entry")

        object_id = obj.get("id")
        object_type = obj.get("type")
        if not isinstance(object_id, str) or not object_type:
            raise ValueError("STIX object is missing id or type")

        if object_id in seen_ids:
            raise ValueError(f"Duplicate STIX object ID: {object_id}")
        seen_ids.add(object_id)

        seed_id = extract_seed_id(obj)
        if seed_id:
            if seed_id in found_seeds:
                raise ValueError(f"Duplicate seed indicator: {seed_id}")
            found_seeds.add(seed_id)

        object_json = json.dumps(
            obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        records.append((object_id, object_type, seed_id, object_json))

    missing = ALLOWED_SEEDS - found_seeds
    if missing:
        raise ValueError(
            "Missing seed indicators: " + ", ".join(sorted(missing))
        )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path), timeout=30)

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS stix_objects (
                object_id TEXT PRIMARY KEY,
                object_type TEXT NOT NULL,
                seed_id TEXT UNIQUE,
                object_json TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_stix_objects_type
            ON stix_objects(object_type)
        """)

        inserted = 0
        with connection:
            for object_id, object_type, seed_id, object_json in records:
                existing = connection.execute(
                    """SELECT object_type, seed_id, object_json
                       FROM stix_objects WHERE object_id = ?""",
                    (object_id,),
                ).fetchone()

                current = (object_type, seed_id, object_json)
                if existing is not None:
                    if existing != current:
                        raise ValueError(
                            f"Conflicting existing STIX object: {object_id}"
                        )
                    continue

                try:
                    connection.execute(
                        """INSERT INTO stix_objects
                           (object_id, object_type, seed_id, object_json)
                           VALUES (?, ?, ?, ?)""",
                        (object_id, object_type, seed_id, object_json),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError(
                        f"Database conflict for object {object_id}"
                    ) from exc

                inserted += 1

        total = connection.execute(
            "SELECT COUNT(*) FROM stix_objects"
        ).fetchone()[0]
        return inserted, total
    finally:
        connection.close()


def main() -> int:
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        inserted, total = load_bundle(BUNDLE_FILE, DB_FILE)
        logging.info(
            "STIX database load successful: inserted=%d total=%d",
            inserted, total,
        )
        print(f"Database: {DB_FILE}")
        print(f"New objects inserted: {inserted}")
        print(f"Total stored objects: {total}")
        print("Seed scope: S001, S002, S003, S004")
        return 0
    except Exception as exc:
        logging.exception("STIX database loading failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
