import csv
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from export_alerts import export_alerts


def make_db(path):
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE TABLE alert_records (
            alert_id TEXT PRIMARY KEY,
            alert_type TEXT NOT NULL,
            seed_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            cluster_id TEXT,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            eligibility TEXT NOT NULL,
            eligibility_reason TEXT,
            first_observed_utc TEXT,
            last_observed_utc TEXT,
            created_at_utc TEXT NOT NULL,
            lead_time_days REAL,
            evidence_ids_json TEXT NOT NULL,
            sources_json TEXT NOT NULL,
            summary TEXT NOT NULL,
            rationale TEXT NOT NULL,
            triaged_at_utc TEXT,
            triaged_by TEXT,
            resolution_note TEXT,
            updated_at_utc TEXT NOT NULL
        );
        CREATE TABLE alert_triage_history (
            history_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            previous_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            previous_severity TEXT NOT NULL,
            new_severity TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            reason TEXT NOT NULL,
            changed_at_utc TEXT NOT NULL
        );
        INSERT INTO infrastructure_nodes VALUES
            ('n1','domain-name','one.example'),
            ('n5','domain-name','five.example');
        INSERT INTO alert_records VALUES
            ('a1','new_observable_in_dataset','S001','n1',NULL,
             'informational','triaged','eligible',NULL,
             '2026-09-30T08:00:00Z',NULL,'2026-09-30T08:00:00Z',
             NULL,'["ev1"]','["VirusTotal"]','Test alert','test rationale',
             '2026-09-30T09:00:00Z','analyst','Reviewed',
             '2026-09-30T09:00:00Z'),
            ('a5','new_observable_in_dataset','S005','n5',NULL,
             'low','new','eligible',NULL,
             NULL,NULL,'2026-09-30T08:00:00Z',
             NULL,'[]','[]','out of scope','test',
             NULL,NULL,NULL,'2026-09-30T08:00:00Z');
        INSERT INTO alert_triage_history VALUES
            ('h1','a1','new','triaged','informational','informational',
             'analyst','Reviewed source evidence.',
             '2026-09-30T09:00:00Z');
        """)


def test_exports_only_allowed_scope(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    out_json = tmp_path / "alerts.json"
    out_csv = tmp_path / "alerts.csv"

    count = export_alerts(db, out_json, out_csv)
    assert count == 1

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["alert_count"] == 1
    assert data["alerts"][0]["seed_id"] == "S001"
    assert data["alerts"][0]["status"] == "triaged"


def test_exports_triage_history(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    out_json = tmp_path / "alerts.json"
    out_csv = tmp_path / "alerts.csv"
    export_alerts(db, out_json, out_csv)

    data = json.loads(out_json.read_text(encoding="utf-8"))
    history = data["alerts"][0]["triage_history"]
    assert len(history) == 1
    assert history[0]["new_status"] == "triaged"

    with out_csv.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert json.loads(rows[0]["triage_history"])[0]["reviewer"] == "analyst"


def test_rejects_invalid_evidence_json(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE alert_records SET evidence_ids_json='not-json' WHERE alert_id='a1'"
        )

    with pytest.raises(ValueError, match="Invalid JSON"):
        export_alerts(db, tmp_path / "a.json", tmp_path / "a.csv")


def test_missing_database_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_alerts(
            tmp_path / "missing.db",
            tmp_path / "a.json",
            tmp_path / "a.csv",
        )
