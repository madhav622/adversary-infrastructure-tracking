import sys
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.false_link_review import load_false_link_candidates


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
            source_name TEXT NOT NULL,
            raw_file_path TEXT
        );
        CREATE TABLE infrastructure_edges (
            edge_id TEXT PRIMARY KEY,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            first_seen_utc TEXT,
            last_seen_utc TEXT,
            rationale TEXT NOT NULL
        );
        INSERT INTO infrastructure_nodes VALUES
            ('ep1','network-endpoint','seed1'),
            ('ep2','network-endpoint','seed2'),
            ('d1','domain-name','shared.example'),
            ('d2','domain-name','unique.example');
        INSERT INTO seed_anchors VALUES
            ('S001','ep1'), ('S002','ep2');
        INSERT INTO evidence_records VALUES
            ('ev1','VirusTotal','data/raw/S001.json'),
            ('ev2','Shodan','data/raw/S002.json'),
            ('ev3','VirusTotal','data/raw/S001-unique.json');
        INSERT INTO infrastructure_edges VALUES
            ('e1','ep1','d1','co-observed-in-evidence',0.2,
             'candidate','ev1',NULL,NULL,'weak link'),
            ('e2','ep2','d1','co-observed-in-evidence',0.2,
             'candidate','ev2',NULL,NULL,'weak link'),
            ('e3','ep1','d2','co-observed-in-evidence',0.2,
             'candidate','ev3',NULL,NULL,'weak link'),
            ('e4','ep1','d2','co-observed-in-evidence',0.9,
             'candidate','ev1',NULL,NULL,'higher score'),
            ('e5','ep1','d2','co-observed-in-evidence',0.2,
             'rejected','ev1',NULL,NULL,'rejected');
        """)


def test_lists_weak_candidates_and_overlap(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = load_false_link_candidates(db)

    assert len(result) == 3
    shared = result[result["target"] == "shared.example"]
    assert len(shared) == 2
    assert (shared["seed_overlap"] == 2).all()
    assert (shared["review_hint"] == "Repeated across seeds — inspect").all()


def test_filters_by_seed(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = load_false_link_candidates(db, "S001")

    assert set(result["seed_id"]) == {"S001"}
    assert len(result) == 2


def test_rejects_out_of_scope_seed(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with pytest.raises(ValueError, match="outside allowed scope"):
        load_false_link_candidates(db, "S005")


def test_rejects_invalid_confidence(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with pytest.raises(ValueError, match="between 0 and 1"):
        load_false_link_candidates(db, max_confidence=1.5)
