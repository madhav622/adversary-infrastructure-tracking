import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.source_quality import (
    get_source_quality,
    get_source_coverage,
)


def make_db(path):
    with sqlite3.connect(path) as conn:
        conn.execute("""
            CREATE TABLE evidence_records (
                evidence_id TEXT PRIMARY KEY,
                seed_id TEXT,
                source_name TEXT NOT NULL,
                source_reference TEXT,
                raw_sha256 TEXT,
                observed_at_utc TEXT,
                details_json TEXT NOT NULL
            )
        """)
        conn.executemany("""
            INSERT INTO evidence_records
            (evidence_id,seed_id,source_name,source_reference,
             raw_sha256,observed_at_utc,details_json)
            VALUES (?,?,?,?,?,?,?)
        """, [
            ("e1", "S001", "VirusTotal", "https://example.com/1",
             "a" * 64, "2026-09-30T08:00:00Z", "{}"),
            ("e2", "S002", "VirusTotal", "https://example.com/2",
             "b" * 64, "2026-09-30T09:00:00Z", "{}"),
            ("e3", "S001", "Shodan", None,
             None, None, "{}"),
        ])


def test_source_quality_summary(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = get_source_quality(db)

    assert set(result["source_name"]) == {"VirusTotal", "Shodan"}
    vt = result[result["source_name"] == "VirusTotal"].iloc[0]
    assert vt["evidence_records"] == 2
    assert vt["seed_coverage"] == 2
    assert vt["sha256_present_records"] == 2
    assert vt["reference_records"] == 2
    assert vt["timestamp_records"] == 2


def test_source_quality_seed_filter(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = get_source_quality(db, "S001")

    assert set(result["source_name"]) == {"VirusTotal", "Shodan"}
    assert result["evidence_records"].sum() == 2
    assert result["seed_coverage"].sum() == 2


def test_source_coverage(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = get_source_coverage(db)

    assert len(result) == 3
    assert set(result["seed_id"]) == {"S001", "S002"}


def test_rejects_out_of_scope_seed(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    with pytest.raises(ValueError, match="outside allowed scope"):
        get_source_quality(db, "S005")
