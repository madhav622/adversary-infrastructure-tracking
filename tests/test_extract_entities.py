import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from extract_entities import extract_entities, extract_from_payload
from entity_validation import registrable_domain, shared_infrastructure_match


def test_extracts_only_valid_field_aware_observables():
    payload = {
        "domain": "sub.evil.example.com",
        "ip_address": "8.8.8.8",
        "sha256": "a" * 64,
        "source_reference": "https://www.virustotal.com/gui/file/abc",
        "popular_threat_label": "trojan.sliver",
        "files_referring": [{"filename": "ut1-phishing.txt"}],
        "whois": {"inetnum": "101.42.0.0 - 101.43.255.255"},
        "vendor": "alphamountain.ai",
    }
    entities = extract_from_payload(payload)
    assert ("domain-name", "sub.evil.example.com", "domain") in entities
    assert ("ipv4-addr", "8.8.8.8", "ip_address") in entities
    assert ("file-hash-sha256", "a" * 64, "sha256") in entities
    values = {value for _, value, _ in entities}
    assert "trojan.sliver" not in values
    assert "ut1-phishing.txt" not in values
    assert "101.42.0.0" not in values
    assert "101.43.255.255" not in values
    assert "alphamountain.ai" not in values
    assert not any("virustotal.com" in value for value in values)
    assert not any(kind in {"ipv4-addr", "ipv6-addr"} for kind, value, path in extract_from_payload({"ip_address": "192.0.2.10"}))


def test_registrable_domain_collapses_subdomains():
    assert registrable_domain("a.luode.vip") == "luode.vip"
    assert registrable_domain("b.luode.vip") == "luode.vip"


def test_cloudflare_ip_is_identified_as_shared_infrastructure():
    match = shared_infrastructure_match("104.21.9.123")
    assert match is not None
    assert match["provider"] == "Cloudflare"
    assert "shared" in match["reason"].casefold()


def _make_extraction_db(path):
    with sqlite3.connect(path) as conn:
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
            source_node_id TEXT,
            target_node_id TEXT,
            relationship_type TEXT,
            first_seen_utc TEXT,
            last_seen_utc TEXT,
            confidence REAL,
            evidence_id TEXT,
            status TEXT,
            rationale TEXT
        );
        CREATE TABLE alert_records (
            alert_id TEXT PRIMARY KEY,
            alert_type TEXT,
            seed_id TEXT,
            node_id TEXT,
            cluster_id TEXT,
            severity TEXT,
            status TEXT,
            first_observed_utc TEXT,
            last_observed_utc TEXT,
            created_at_utc TEXT,
            lead_time_days REAL,
            evidence_ids_json TEXT,
            sources_json TEXT,
            summary TEXT,
            rationale TEXT,
            triaged_at_utc TEXT,
            triaged_by TEXT,
            resolution_note TEXT,
            updated_at_utc TEXT
        );
        INSERT INTO infrastructure_nodes VALUES
            ('endpoint--test','network-endpoint','8.8.8.8:31337','8.8.8.8:31337',
             '{"ip_address":"8.8.8.8","port":31337}','2026-09-30T00:00:00Z'),
            ('observable--legacy','domain-name','trojan.sliver','trojan.sliver',
             '{"extraction_method":"passive-evidence-v1"}','2026-09-30T00:00:00Z');
        INSERT INTO seed_anchors VALUES (
            'S001','endpoint--test','2026-09-30T00:00:00Z',NULL,NULL,'manual',NULL,'{}'
        );
        INSERT INTO evidence_records VALUES (
            'evidence--test','S001','manual','raw-json',NULL,NULL,NULL,NULL,
            '{"domain":"evil.example.com","ip_address":"8.8.8.8"}'
        );
        INSERT INTO infrastructure_edges VALUES (
            'edge--legacy','endpoint--test','observable--legacy','co-observed-in-evidence',
            NULL,NULL,0.2,'evidence--test','candidate','old extraction'
        );
        INSERT INTO alert_records VALUES (
            'alert--legacy','new_observable_in_dataset','S001','observable--legacy',NULL,
            'informational','new',NULL,NULL,'2026-09-30T00:00:00Z',NULL,'[]','[]',
            'old alert','old extraction',NULL,NULL,NULL,'2026-09-30T00:00:00Z'
        );
        """)


def test_extraction_is_idempotent_and_retires_stale_artifacts(tmp_path):
    db = tmp_path / "intel.db"
    _make_extraction_db(db)

    result = extract_entities(db)
    assert result[0] == 1
    assert result[1] == 2

    with sqlite3.connect(db) as conn:
        node = conn.execute("SELECT lifecycle_status,retirement_reason,attributes_json FROM infrastructure_nodes WHERE node_id='observable--legacy'").fetchone()
        edge = conn.execute("SELECT lifecycle_status,retirement_reason FROM infrastructure_edges WHERE edge_id='edge--legacy'").fetchone()
        alert = conn.execute("SELECT lifecycle_status,eligibility FROM alert_records WHERE alert_id='alert--legacy'").fetchone()
    assert node[0] == "retired"
    assert "metadata" in node[1].casefold() or "pseudo-tld" in node[1].casefold()
    assert json.loads(node[2])["lifecycle_status"] == "retired"
    assert edge[0] == "retired"
    assert alert == ("retired", "excluded")

    second = extract_entities(db)
    assert second[0] == 0
    assert second[1] == 0
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT lifecycle_status FROM infrastructure_nodes WHERE node_id='observable--legacy'").fetchone()[0] == "retired"
        assert conn.execute("SELECT lifecycle_status FROM infrastructure_edges WHERE edge_id='edge--legacy'").fetchone()[0] == "retired"


def test_rejects_missing_database(tmp_path):
    with pytest.raises(FileNotFoundError):
        extract_entities(tmp_path / "missing.db")
