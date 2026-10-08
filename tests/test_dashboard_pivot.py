import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.pivot import find_seed, find_pivots


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
            raw_file_path TEXT,
            raw_sha256 TEXT
        );
        CREATE TABLE infrastructure_edges (
            edge_id TEXT PRIMARY KEY,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence REAL NOT NULL,
            first_seen_utc TEXT,
            last_seen_utc TEXT,
            evidence_id TEXT NOT NULL,
            rationale TEXT NOT NULL
        );

        INSERT INTO infrastructure_nodes VALUES
            ('ep1','network-endpoint','1.14.73.118:34091'),
            ('dom1','domain-name','example.test'),
            ('ep2','network-endpoint','101.42.108.164:31337');
        INSERT INTO seed_anchors VALUES
            ('S001','ep1'), ('S002','ep2');
        INSERT INTO evidence_records VALUES
            ('ev1','VirusTotal','data/raw/S001_test.json','abc123'),
            ('ev2','Shodan','data/raw/S002_test.json','def456');
        INSERT INTO infrastructure_edges VALUES
            ('edge1','ep1','dom1','co-observed-in-evidence',
             'candidate',0.2,'2026-09-30T00:00:00Z',NULL,'ev1','test rationale'),
            ('edge2','ep2','dom1','co-observed-in-evidence',
             'candidate',0.2,'2026-09-30T00:00:00Z',NULL,'ev2','other rationale'),
            ('edge3','ep1','dom1','co-observed-in-evidence',
             'rejected',0.2,NULL,NULL,'ev1','rejected edge'),
            ('edge4','ep1','dom1','unverified-link',
             'candidate',0.8,NULL,NULL,'ev1','wrong type');
        """)


def test_lookup_seed_by_id(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = find_seed("S001", db)
    assert len(result) == 1
    assert result.iloc[0]["endpoint"] == "1.14.73.118:34091"


def test_lookup_seed_by_ioc(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = find_seed("1.14.73.118:34091", db)
    assert len(result) == 1
    assert result.iloc[0]["seed_id"] == "S001"


def test_pivots_show_evidence_backed_edges_only(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    result = find_pivots("S001", db)
    assert len(result) == 1
    assert result.iloc[0]["evidence_id"] == "ev1"
    assert result.iloc[0]["source_name"] == "VirusTotal"
    assert result.iloc[0]["pivot_strength"] == 0.2


def test_rejects_out_of_scope_seed(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with pytest.raises(ValueError, match="outside the allowed scope"):
        find_pivots("S005", db)


def test_empty_seed_query(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    assert find_seed(" ", db).empty
