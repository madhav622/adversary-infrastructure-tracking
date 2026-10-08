import sys
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_candidate_edges import build_candidate_edges


def make_db(path):
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY
        );
        CREATE TABLE seed_anchors (
            seed_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL
        );
        CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY,
            seed_id TEXT,
            raw_file_path TEXT,
            observed_at_utc TEXT
        );
        CREATE TABLE entity_observations (
            evidence_id TEXT,
            node_id TEXT,
            field_path TEXT
        );
        CREATE TABLE infrastructure_edges (
            edge_id TEXT PRIMARY KEY,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            first_seen_utc TEXT,
            last_seen_utc TEXT,
            confidence REAL NOT NULL,
            evidence_id TEXT NOT NULL,
            status TEXT NOT NULL,
            rationale TEXT NOT NULL
        );

        INSERT INTO infrastructure_nodes VALUES
            ('endpoint--1'), ('domain--1');
        INSERT INTO seed_anchors VALUES ('S001','endpoint--1');
        INSERT INTO evidence_records VALUES
            ('evidence--1','S001','data/raw/S001_test.json',
             '2026-09-30T00:00:00Z');
        INSERT INTO entity_observations VALUES
            ('evidence--1','endpoint--1','ip'),
            ('evidence--1','domain--1','domain'),
            ('evidence--1','domain--1','dns.domain');
        """)


def test_creates_candidate_and_is_idempotent(tmp_path):
    db = tmp_path / "test.db"
    make_db(db)

    assert build_candidate_edges(db) == (1, 1)
    assert build_candidate_edges(db) == (0, 1)

    with sqlite3.connect(db) as conn:
        edge = conn.execute("""
            SELECT relationship_type, confidence, status, rationale
            FROM infrastructure_edges
        """).fetchone()

    assert edge[0] == "co-observed-in-evidence"
    assert edge[1] == 0.2
    assert edge[2] == "candidate"
    assert "not proof" in edge[3]
    assert "dns.domain" in edge[3]


def test_skips_self_relationships(tmp_path):
    db = tmp_path / "test.db"
    make_db(db)

    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM entity_observations")
        conn.execute(
            "INSERT INTO entity_observations VALUES (?,?,?)",
            ("evidence--1", "endpoint--1", "ip"),
        )

    assert build_candidate_edges(db) == (0, 0)


def test_missing_database_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_candidate_edges(tmp_path / "missing.db")


def test_retires_existing_edge_when_target_becomes_shared(tmp_path):
    db = tmp_path / "test.db"
    make_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE infrastructure_nodes ADD COLUMN attributes_json TEXT NOT NULL DEFAULT '{}' ")
    assert build_candidate_edges(db) == (1, 1)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE infrastructure_nodes SET attributes_json=? WHERE node_id='domain--1'", ('{"is_shared_infrastructure":true}',))
    assert build_candidate_edges(db) == (0, 1)
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT lifecycle_status,retirement_reason FROM infrastructure_edges").fetchone()
    assert row[0] == "retired"
    assert "shared infrastructure" in row[1]
