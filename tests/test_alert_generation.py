import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_alerts import generate_alerts


def make_db(path):
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE TABLE seed_anchors (
            seed_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL
        );
        CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY,
            seed_id TEXT,
            source_name TEXT,
            observed_at_utc TEXT
        );
        CREATE TABLE entity_observations (
            evidence_id TEXT,
            node_id TEXT
        );
        CREATE TABLE clusters (
            cluster_id TEXT PRIMARY KEY
        );
        CREATE TABLE cluster_memberships (
            cluster_id TEXT,
            node_id TEXT,
            membership_type TEXT
        );
        INSERT INTO infrastructure_nodes VALUES
            ('ep1','network-endpoint','1.14.73.118:34091'),
            ('dom1','domain-name','sample.example'),
            ('hash1','file-hash-sha256','aabbcc');
        INSERT INTO seed_anchors VALUES ('S001','ep1');
        INSERT INTO evidence_records VALUES
            ('ev1','S001','VirusTotal','2026-09-30T08:00:00Z'),
            ('ev2','S001','Shodan','2026-09-30T09:00:00Z');
        INSERT INTO entity_observations VALUES
            ('ev1','ep1'), ('ev1','dom1'), ('ev2','dom1'),
            ('ev2','hash1');
        """)


def test_creates_real_evidence_alerts(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    new, updated, total, statuses = generate_alerts(db)
    assert new == 2
    assert updated == 0
    assert total == 2
    assert statuses["new"] == 2

    with sqlite3.connect(db) as conn:
        row = conn.execute("""
            SELECT severity,status,lead_time_days,evidence_ids_json,
                   cluster_id,first_observed_utc,last_observed_utc
            FROM alert_records
            WHERE node_id='dom1'
        """).fetchone()

    assert row[0] == "informational"
    assert row[1] == "new"
    assert row[2] is None
    assert json.loads(row[3]) == ["ev1", "ev2"]
    assert row[4] is None
    assert row[5] == "2026-09-30T08:00:00Z"
    assert row[6] == "2026-09-30T09:00:00Z"


def test_is_idempotent(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    assert generate_alerts(db)[0:3] == (2, 0, 2)
    assert generate_alerts(db)[0:3] == (0, 0, 2)


def test_preserves_existing_triage_status(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    generate_alerts(db)

    with sqlite3.connect(db) as conn:
        conn.execute("""
            UPDATE alert_records SET status='triaged'
            WHERE node_id='dom1'
        """)

    generate_alerts(db)
    with sqlite3.connect(db) as conn:
        status = conn.execute("""
            SELECT status FROM alert_records WHERE node_id='dom1'
        """).fetchone()[0]

    assert status == "triaged"


def test_missing_database_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        generate_alerts(tmp_path / "missing.db")
