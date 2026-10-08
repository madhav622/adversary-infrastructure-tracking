from __future__ import annotations

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"
JSON_OUT = ROOT / "exports" / "siem_ioc_feed.json"
CSV_OUT = ROOT / "exports" / "siem_ioc_feed.csv"
LOG = ROOT / "logs" / "export_siem_feed.log"

ALLOWED = ("S001", "S002", "S003", "S004")

FIELDS = [
    "seed_id",
    "indicator_id",
    "ioc",
    "ioc_type",
    "stix_pattern",
    "first_seen_utc",
    "last_seen_utc",
    "observed_at_utc",
    "source",
    "source_reference",
    "source_confidence_pct",
    "source_confidence_label",
    "asn",
    "country",
    "is_compromised",
    "review_status",
    "notes",
]


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def create_records(db_path: Path) -> list[dict]:
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    with sqlite3.connect(str(db_path), timeout=30) as conn:
        rows = conn.execute("""
            SELECT
                a.seed_id,
                a.first_seen_utc,
                a.last_seen_utc,
                a.observed_at_utc,
                a.source,
                a.source_reference,
                a.metadata_json,
                o.object_id,
                o.object_json
            FROM seed_anchors a
            JOIN stix_objects o ON o.seed_id = a.seed_id
            WHERE a.seed_id IN ('S001','S002','S003','S004')
              AND o.object_type = 'indicator'
            ORDER BY a.seed_id
        """).fetchall()

    records = []
    found = set()

    for row in rows:
        (
            seed_id, first_seen, last_seen, observed, source,
            reference, metadata_json, object_id, object_json,
        ) = row

        if seed_id not in ALLOWED:
            raise ValueError(f"Out-of-scope seed: {seed_id}")
        if seed_id in found:
            raise ValueError(f"Duplicate indicator for {seed_id}")

        metadata = json.loads(metadata_json)
        indicator = json.loads(object_json)

        if not isinstance(metadata, dict) or not isinstance(indicator, dict):
            raise ValueError(f"Invalid stored record: {seed_id}")
        if indicator.get("id") != object_id:
            raise ValueError(f"STIX ID mismatch for {seed_id}")
        if indicator.get("pattern_type") != "stix":
            raise ValueError(f"Unexpected pattern type for {seed_id}")

        ioc = (metadata.get("ioc") or "").strip()
        ioc_type = (metadata.get("ioc_type") or "").strip()
        if not ioc or not ioc_type or not indicator.get("pattern"):
            raise ValueError(f"Incomplete indicator data for {seed_id}")

        confidence = metadata.get("source_confidence_pct")
        if confidence not in (None, ""):
            confidence = int(confidence)
            if not 0 <= confidence <= 100:
                raise ValueError(
                    f"Source confidence outside 0-100 for {seed_id}"
                )
        else:
            confidence = None

        compromised = metadata.get("is_compromised")
        if isinstance(compromised, str):
            if compromised.strip().casefold() == "true":
                compromised = True
            elif compromised.strip().casefold() == "false":
                compromised = False
            elif not compromised.strip():
                compromised = None

        records.append({
            "seed_id": seed_id,
            "indicator_id": object_id,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "stix_pattern": indicator["pattern"],
            "first_seen_utc": first_seen,
            "last_seen_utc": last_seen,
            "observed_at_utc": observed,
            "source": source,
            "source_reference": reference,
            "source_confidence_pct": confidence,
            "source_confidence_label": metadata.get(
                "source_confidence_label"
            ) or None,
            "asn": metadata.get("asn") or None,
            "country": metadata.get("country") or None,
            "is_compromised": compromised,
            "review_status": "analyst-review-required",
            "notes": metadata.get("notes") or "",
        })
        found.add(seed_id)

    missing = set(ALLOWED) - found
    if missing:
        raise ValueError(
            "Missing seed indicators: " + ", ".join(sorted(missing))
        )

    return records


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def export_feed(records: list[dict]) -> None:
    document = {
        "feed_name": "Adversary Infrastructure Tracking IOC Feed",
        "schema_version": "1.0",
        "generated_at_utc": now_utc(),
        "scope": list(ALLOWED),
        "review_policy": (
            "Indicators require analyst review. This feed does not "
            "instruct automatic blocking."
        ),
        "indicator_count": len(records),
        "indicators": records,
    }

    json_text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    from io import StringIO
    buffer = StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=FIELDS,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(records)

    atomic_write(JSON_OUT, json_text)
    atomic_write(CSV_OUT, buffer.getvalue())


def main() -> int:
    logging.basicConfig(
        filename=str(LOG),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        records = create_records(DB)
        export_feed(records)
        logging.info("Exported %d seed indicators", len(records))

        print(f"JSON feed: {JSON_OUT}")
        print(f"CSV feed: {CSV_OUT}")
        print(f"Exported indicators: {len(records)}")
        print("Scope: S001, S002, S003, S004")
        print("Review status: analyst-review-required")
        print("Automatic blocking: not enabled")
        return 0
    except Exception as exc:
        logging.exception("SIEM export failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
