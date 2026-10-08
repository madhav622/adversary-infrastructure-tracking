import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_final_analyst_report import (
    build_report_data,
    render_markdown,
    atomic_write,
)


def make_db(path):
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE stix_objects (
            object_id TEXT PRIMARY KEY, object_type TEXT,
            seed_id TEXT, object_json TEXT
        );
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY, node_type TEXT, value TEXT,
            normalized_value TEXT, attributes_json TEXT, created_at_utc TEXT
        );
        CREATE TABLE seed_anchors (
            seed_id TEXT PRIMARY KEY, node_id TEXT, first_seen_utc TEXT,
            last_seen_utc TEXT, observed_at_utc TEXT, source TEXT,
            source_reference TEXT, metadata_json TEXT
        );
        CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY, seed_id TEXT,
            source_name TEXT, evidence_type TEXT,
            source_reference TEXT, raw_file_path TEXT,
            raw_sha256 TEXT, observed_at_utc TEXT, details_json TEXT
        );
        CREATE TABLE entity_observations (
            evidence_id TEXT, node_id TEXT, field_path TEXT,
            extraction_method TEXT
        );
        CREATE TABLE infrastructure_edges (
            edge_id TEXT PRIMARY KEY, source_node_id TEXT,
            target_node_id TEXT, relationship_type TEXT,
            first_seen_utc TEXT, last_seen_utc TEXT,
            confidence REAL, evidence_id TEXT, status TEXT,
            rationale TEXT
        );
        CREATE TABLE cluster_runs (
            run_id TEXT PRIMARY KEY, algorithm TEXT,
            parameters_json TEXT, status TEXT,
            started_at_utc TEXT, completed_at_utc TEXT
        );
        CREATE TABLE clusters (
            cluster_id TEXT PRIMARY KEY, run_id TEXT,
            label TEXT, confidence REAL, summary TEXT
        );
        CREATE TABLE cluster_memberships (
            cluster_id TEXT, node_id TEXT, membership_type TEXT
        );
        CREATE TABLE cluster_pair_scores (
            run_id TEXT, seed_a TEXT, seed_b TEXT, score REAL,
            status TEXT, shared_observables_json TEXT
        );
        CREATE TABLE alert_records (
            alert_id TEXT PRIMARY KEY, alert_type TEXT, seed_id TEXT,
            node_id TEXT, cluster_id TEXT, severity TEXT, status TEXT,
            eligibility TEXT, eligibility_reason TEXT,
            first_observed_utc TEXT, last_observed_utc TEXT,
            created_at_utc TEXT, lead_time_days REAL,
            evidence_ids_json TEXT, sources_json TEXT, summary TEXT,
            rationale TEXT, triaged_at_utc TEXT, triaged_by TEXT,
            resolution_note TEXT, updated_at_utc TEXT
        );
        CREATE TABLE alert_triage_history (
            history_id TEXT PRIMARY KEY, alert_id TEXT,
            previous_status TEXT, new_status TEXT,
            previous_severity TEXT, new_severity TEXT,
            reviewer TEXT, reason TEXT, changed_at_utc TEXT
        );

        INSERT INTO infrastructure_nodes VALUES
            ('ep1','network-endpoint','192.0.2.1:31337',
             '192.0.2.1:31337','{}','2026-09-30T00:00:00Z');
        INSERT INTO seed_anchors VALUES
            ('S001','ep1','2026-09-30T00:00:00Z',NULL,NULL,
             'test',NULL,'{}'),
            ('S002','ep1','2026-09-30T00:00:00Z',NULL,NULL,
             'test',NULL,'{}'),
            ('S003','ep1','2026-09-30T00:00:00Z',NULL,NULL,
             'test',NULL,'{}'),
            ('S004','ep1','2026-09-30T00:00:00Z',NULL,NULL,
             'test',NULL,'{}');

        INSERT INTO stix_objects VALUES
            ('identity--1','identity',NULL,'{}');
        INSERT INTO evidence_records VALUES
            ('ev1','S001','VirusTotal','details',NULL,NULL,
             NULL,'2026-09-30T00:00:00Z','{}');
        INSERT INTO cluster_runs VALUES
            ('run1','test','{"threshold":0.5}','completed',
             '2026-09-30T00:00:00Z','2026-09-30T00:00:01Z');
        INSERT INTO cluster_pair_scores VALUES
            ('run1','S001','S002',0.0,'below_threshold','[]');
        INSERT INTO alert_records VALUES
            ('a1','new_observable_in_dataset','S001','ep1',NULL,
             'informational','triaged','eligible',NULL,
             NULL,NULL,'2026-09-30T00:00:00Z',NULL,
             '["ev1"]','["VirusTotal"]','Alert summary',
             'Alert rationale','2026-09-30T01:00:00Z',
             'analyst','Reviewed','2026-09-30T01:00:00Z');
        INSERT INTO alert_triage_history VALUES
            ('h1','a1','new','triaged','informational','informational',
             'analyst','Reviewed source evidence.',
             '2026-09-30T01:00:00Z');
        """)


def test_collects_scoped_alerts_and_history(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    data = build_report_data(db)
    assert len(data["seeds"]) == 4
    assert data["alert_summary"]["total"] == 1
    assert data["alerts"][0]["status"] == "triaged"
    assert len(data["triage_history"]) == 1
    assert data["triage_history"][0]["new_status"] == "triaged"


def test_report_contains_all_sections(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    report = render_markdown(build_report_data(db))

    for heading in (
        "Executive summary", "Seed inventory",
        "Clustering", "Alert summary",
        "Alert register", "Analyst triage history",
        "Limitations",
    ):
        assert heading in report


def test_report_outputs_are_valid(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    data = build_report_data(db)

    report_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"
    atomic_write(report_path, render_markdown(data))
    atomic_write(
        json_path,
        json.dumps(data, indent=2, ensure_ascii=False),
    )

    assert report_path.is_file()
    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["alert_summary"]["total"] == 1
    assert parsed["scope"] == ["S001", "S002", "S003", "S004"]


def test_missing_database_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_report_data(tmp_path / "missing.db")
