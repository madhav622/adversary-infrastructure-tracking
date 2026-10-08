import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.alerts import (
    get_alerts, get_alert_history, update_alert, allowed_statuses
)


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
            updated_at_utc TEXT NOT NULL,
            eligibility TEXT NOT NULL DEFAULT 'eligible',
            eligibility_reason TEXT,
            eligibility_updated_at_utc TEXT
                );
        INSERT INTO infrastructure_nodes VALUES
            ('n1','domain-name','one.example'),
            ('n2','ipv4-addr','192.0.2.10');
        INSERT INTO alert_records (
            alert_id,alert_type,seed_id,node_id,cluster_id,
            severity,status,first_observed_utc,last_observed_utc,
            created_at_utc,lead_time_days,evidence_ids_json,sources_json,
            summary,rationale,triaged_at_utc,triaged_by,resolution_note,
            updated_at_utc
        ) VALUES
            ('a1','new_observable_in_dataset','S001','n1',NULL,
             'informational','new','2026-09-30T08:00:00Z',NULL,
             '2026-09-30T08:00:00Z',NULL,'["ev1"]','["VirusTotal"]',
             'Test alert','Evidence found',NULL,NULL,NULL,
             '2026-09-30T08:00:00Z'),
            ('a2','new_observable_in_dataset','S002','n2',NULL,
             'low','triaged','2026-09-30T09:00:00Z',NULL,
             '2026-09-30T09:00:00Z',NULL,'["ev2"]','["Shodan"]',
             'Second alert','Evidence found','2026-09-30T10:00:00Z',
             'analyst',NULL,'2026-09-30T10:00:00Z');
        """)


def test_alert_list_and_filters(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    assert len(get_alerts(db)) == 2
    assert len(get_alerts(db, status="new")) == 1
    assert len(get_alerts(db, severity="low")) == 1
    assert len(get_alerts(db, seed_id="S001")) == 1


def test_triage_and_audit_history(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    saved = update_alert(
        "a1", "triaged", "medium", "analyst",
        "Reviewed source and supporting passive evidence.", db
    )
    assert saved["status"] == "triaged"
    assert saved["severity"] == "medium"

    history = get_alert_history("a1", db)
    assert len(history) == 1
    assert history.iloc[0]["previous_status"] == "new"
    assert history.iloc[0]["new_status"] == "triaged"


def test_blocked_is_a_manual_status_update(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    update_alert("a1", "triaged", "low", "analyst", "Reviewed alert evidence.", db)
    update_alert("a1", "blocked", "high", "analyst", "Manually marked after SOC action.", db)

    result = get_alerts(db, status="blocked")
    assert len(result) == 1
    assert result.iloc[0]["severity"] == "high"


def test_invalid_status_transition_is_rejected(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with pytest.raises(ValueError, match="Invalid transition"):
        update_alert(
            "a1", "blocked", "high", "analyst",
            "Cannot skip the triage step.", db
        )


def test_out_of_scope_and_invalid_fields_rejected(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    with pytest.raises(ValueError, match="allowed scope"):
        get_alerts(db, seed_id="S005")

    with pytest.raises(ValueError, match="Invalid alert severity"):
        update_alert("a1", "triaged", "urgent", "analyst", "Review reason.", db)

    with pytest.raises(ValueError, match="5-2000"):
        update_alert("a1", "triaged", "low", "analyst", "No", db)


def test_missing_alert_rejected(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with pytest.raises(ValueError, match="does not exist"):
        update_alert(
            "missing", "triaged", "low", "analyst",
            "Reviewed evidence.", db
        )


def test_excluded_alert_cannot_be_triaged_backend(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE alert_records SET eligibility='excluded', eligibility_reason='Shared infrastructure' WHERE alert_id='a1'")
    with pytest.raises(ValueError, match="Triage disabled"):
        update_alert(
            "a1", "triaged", "low", "analyst",
            "Reviewed but not eligible for triage.", db
        )
