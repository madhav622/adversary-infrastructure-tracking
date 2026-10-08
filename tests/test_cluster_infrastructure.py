import sys
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cluster_infrastructure import (
    score_shared_observables,
    build_clusters,
    THRESHOLD,
)


def test_single_domain_below_threshold():
    shared = [{"node_id": "d1", "node_type": "domain-name"}]
    assert score_shared_observables(shared) == 0.35
    assert score_shared_observables(shared) < THRESHOLD


def test_two_distinct_domains_combine():
    shared = [
        {"node_id": "d1", "node_type": "domain-name"},
        {"node_id": "d2", "node_type": "domain-name"},
    ]
    assert score_shared_observables(shared) == 0.5775


def test_duplicate_observable_counts_once():
    shared = [
        {"node_id": "d1", "node_type": "domain-name"},
        {"node_id": "d1", "node_type": "domain-name"},
    ]
    assert score_shared_observables(shared) == 0.35


def test_ip_is_not_scored():
    shared = [
        {"node_id": "ip1", "node_type": "ipv4-addr"},
        {"node_id": "ep1", "node_type": "network-endpoint"},
    ]
    assert score_shared_observables(shared) == 0.0


def test_pairwise_clustering(tmp_path):
    db = tmp_path / "intel.db"

    with sqlite3.connect(db) as conn:
        conn.executescript("""
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            attributes_json TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            UNIQUE(node_type, normalized_value)
        );
        CREATE TABLE seed_anchors (
            seed_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL REFERENCES infrastructure_nodes(node_id),
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT,
            observed_at_utc TEXT,
            source TEXT NOT NULL,
            source_reference TEXT,
            metadata_json TEXT NOT NULL
        );
        CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY,
            seed_id TEXT,
            source_name TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            source_reference TEXT,
            raw_file_path TEXT,
            raw_sha256 TEXT,
            observed_at_utc TEXT,
            details_json TEXT NOT NULL
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
            ('ep1','network-endpoint','ip:1','ip:1','{}','2026-09-30'),
            ('ep2','network-endpoint','ip:2','ip:2','{}','2026-09-30'),
            ('ep3','network-endpoint','ip:3','ip:3','{}','2026-09-30'),
            ('ep4','network-endpoint','ip:4','ip:4','{}','2026-09-30'),
            ('d1','domain-name','a.example','a.example','{}','2026-09-30'),
            ('d2','domain-name','b.example','b.example','{}','2026-09-30'),
            ('ip-shared','ipv4-addr','192.0.2.8','192.0.2.8','{}','2026-09-30');

        INSERT INTO seed_anchors VALUES
            ('S001','ep1','2026-09-30',NULL,NULL,'test',NULL,'{}'),
            ('S002','ep2','2026-09-30',NULL,NULL,'test',NULL,'{}'),
            ('S003','ep3','2026-09-30',NULL,NULL,'test',NULL,'{}'),
            ('S004','ep4','2026-09-30',NULL,NULL,'test',NULL,'{}');

        INSERT INTO evidence_records VALUES
            ('e1','S001','test','test',NULL,NULL,NULL,NULL,'{}'),
            ('e2','S002','test','test',NULL,NULL,NULL,NULL,'{}'),
            ('e3','S003','test','test',NULL,NULL,NULL,NULL,'{}');

        INSERT INTO infrastructure_edges VALUES
            ('x1','ep1','d1','co-observed-in-evidence',NULL,NULL,0.2,'e1','candidate',''),
            ('x2','ep1','d2','co-observed-in-evidence',NULL,NULL,0.2,'e1','candidate',''),
            ('x3','ep2','d1','co-observed-in-evidence',NULL,NULL,0.2,'e2','candidate',''),
            ('x4','ep2','d2','co-observed-in-evidence',NULL,NULL,0.2,'e2','candidate',''),
            ('x5','ep1','ip-shared','co-observed-in-evidence',NULL,NULL,0.2,'e1','candidate',''),
            ('x6','ep3','ip-shared','co-observed-in-evidence',NULL,NULL,0.2,'e3','candidate','');
        """)

    run_id, pairs, new_clusters = build_clusters(db)
    assert len(pairs) == 6
    assert new_clusters == 1

    pair = next(
        p for p in pairs
        if (p["seed_a"], p["seed_b"]) == ("S001", "S002")
    )
    assert pair["score"] == 0.5775
    assert pair["status"] == "candidate"

    ip_pair = next(
        p for p in pairs
        if (p["seed_a"], p["seed_b"]) == ("S001", "S003")
    )
    assert ip_pair["score"] == 0.0
    assert ip_pair["status"] == "below_threshold"

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM cluster_memberships"
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT COUNT(*) FROM cluster_pair_scores"
        ).fetchone()[0] == 6

    _, _, second_run_clusters = build_clusters(db)
    assert second_run_clusters == 0
