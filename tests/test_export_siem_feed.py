import sys
import json
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from export_siem_feed import create_records, export_feed


def create_test_db(path, omit=None):
    omit = omit or set()
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY
        );
        CREATE TABLE seed_anchors (
            seed_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT,
            observed_at_utc TEXT,
            source TEXT NOT NULL,
            source_reference TEXT,
            metadata_json TEXT NOT NULL
        );
        CREATE TABLE stix_objects (
            object_id TEXT PRIMARY KEY,
            object_type TEXT NOT NULL,
            seed_id TEXT UNIQUE,
            object_json TEXT NOT NULL
        );
        """)

        for seed, ioc in [
            ("S001", "1.14.73.118:34091"),
            ("S002", "101.42.108.164:31337"),
            ("S003", "103.250.172.230:31337"),
            ("S004", "103.253.42.61:31337"),
        ]:
            if seed in omit:
                continue

            conn.execute(
                "INSERT INTO infrastructure_nodes VALUES (?)",
                (f"ep-{seed}",),
            )
            metadata = {
                "ioc": ioc,
                "ioc_type": "ip:port",
                "source_confidence_pct": "",
                "notes": "test",
            }
            conn.execute(
                """INSERT INTO seed_anchors VALUES
                   (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    seed, f"ep-{seed}", "2026-09-30T00:00:00Z",
                    None, None, "ThreatFox", None,
                    json.dumps(metadata),
                ),
            )
            indicator = {
                "id": f"indicator--{seed}",
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '192.0.2.1']",
            }
            conn.execute(
                """INSERT INTO stix_objects VALUES (?, ?, ?, ?)""",
                (
                    indicator["id"], "indicator", seed,
                    json.dumps(indicator),
                ),
            )


def test_export_scope_and_review_policy(tmp_path):
    db = tmp_path / "intel.db"
    create_test_db(db)
    records = create_records(db)

    assert len(records) == 4
    assert [r["seed_id"] for r in records] == [
        "S001", "S002", "S003", "S004"
    ]
    assert all(
        r["review_status"] == "analyst-review-required"
        for r in records
    )
    assert all(r["source_confidence_pct"] is None for r in records)


def test_rejects_missing_seed(tmp_path):
    db = tmp_path / "intel.db"
    create_test_db(db, omit={"S004"})

    with pytest.raises(ValueError, match="Missing seed indicators"):
        create_records(db)


def test_writes_json_and_csv(tmp_path, monkeypatch):
    import export_siem_feed

    db = tmp_path / "intel.db"
    create_test_db(db)
    monkeypatch.setattr(export_siem_feed, "JSON_OUT", tmp_path / "feed.json")
    monkeypatch.setattr(export_siem_feed, "CSV_OUT", tmp_path / "feed.csv")

    records = create_records(db)
    export_feed(records)

    data = json.loads((tmp_path / "feed.json").read_text(encoding="utf-8"))
    assert data["indicator_count"] == 4
    assert data["scope"] == ["S001", "S002", "S003", "S004"]
    assert (tmp_path / "feed.csv").is_file()
