import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from qualify_alerts import classify_observations, qualify_alerts


def make_db(path):
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE infrastructure_nodes (
            node_id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            value TEXT NOT NULL,
            attributes_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY,
            seed_id TEXT NOT NULL
        );
        CREATE TABLE entity_observations (
            evidence_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            field_path TEXT,
            extraction_method TEXT
        );
        CREATE TABLE alert_records (
            alert_id TEXT PRIMARY KEY,
            seed_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            triaged_at_utc TEXT,
            triaged_by TEXT,
            resolution_note TEXT
        );
        INSERT INTO infrastructure_nodes VALUES
            ('range-ip','ipv4-addr','101.43.255.255','{}'),
            ('host-ip','ipv4-addr','8.8.8.8','{}'),
            ('vendor-domain','domain-name','alphamountain.ai','{}'),
            ('label-domain','domain-name','trojan.sliver','{}'),
            ('mixed-ip','ipv4-addr','8.8.4.4','{}'),
            ('no-context','domain-name','unknown.example.com','{}'),
            ('shared-ip','ipv4-addr','104.21.9.123','{"is_shared_infrastructure":true,"exclusion_reason":"Cloudflare shared proxy/anycast address range."}');
        INSERT INTO evidence_records VALUES
            ('e-range','S002'),('e-host','S001'),('e-vendor','S004'),
            ('e-label','S001'),('e-mixed','S001'),('e-no-context','S003'),
            ('e-shared','S002');
        INSERT INTO entity_observations VALUES
            ('e-range','range-ip','inetnum','passive-evidence-v1'),
            ('e-host','host-ip','ip_address','passive-evidence-v1'),
            ('e-vendor','vendor-domain','vendors[5].name','passive-evidence-v1'),
            ('e-label','label-domain','popular_threat_label','passive-evidence-v1'),
            ('e-mixed','mixed-ip','inetnum','passive-evidence-v1'),
            ('e-mixed','mixed-ip','ip_address','passive-evidence-v1'),
            ('e-shared','shared-ip','contacted_ips[0].ip','passive-evidence-v2');
        INSERT INTO alert_records VALUES
            ('a-range','S002','range-ip','triaged','informational','2026-09-30T00:00:00Z','2026-09-30T01:00:00Z','local-analyst','Old reason'),
            ('a-host','S001','host-ip','new','informational','2026-09-30T00:00:00Z',NULL,NULL,NULL),
            ('a-vendor','S004','vendor-domain','new','informational','2026-09-30T00:00:00Z',NULL,NULL,NULL),
            ('a-label','S001','label-domain','new','informational','2026-09-30T00:00:00Z',NULL,NULL,NULL),
            ('a-mixed','S001','mixed-ip','new','informational','2026-09-30T00:00:00Z',NULL,NULL,NULL),
            ('a-unknown','S003','no-context','new','informational','2026-09-30T00:00:00Z',NULL,NULL,NULL),
            ('a-shared','S002','shared-ip','new','informational','2026-09-30T00:00:00Z',NULL,NULL,NULL);
        """)


def test_range_only_ip_is_excluded():
    status, reason = classify_observations("ipv4-addr", ["inetnum"])
    assert status == "excluded"
    assert "inetnum" in reason


def test_explicit_public_host_ip_is_eligible():
    assert classify_observations("ipv4-addr", ["ip_address"], value="8.8.8.8") == ("eligible", None)


def test_non_global_ip_is_excluded():
    status, reason = classify_observations("ipv4-addr", ["ip_address"], value="192.0.2.10")
    assert status == "excluded"
    assert "Non-public" in reason


def test_vendor_domain_is_excluded():
    status, reason = classify_observations("domain-name", ["vendors[5].name"], value="alphamountain.ai")
    assert status == "excluded"
    assert "vendors[5].name" in reason


def test_pseudo_tld_domain_is_excluded():
    status, reason = classify_observations("domain-name", ["domain"], value="trojan.sliver")
    assert status == "excluded"
    assert "pseudo-TLD" in reason
    assert classify_observations("domain-name", ["popular_threat_label"], value="trojan.sliver")[0] == "excluded"


def test_valid_path_takes_precedence_but_value_still_validated():
    assert classify_observations("ipv4-addr", ["inetnum", "ip_address"], value="8.8.4.4") == ("eligible", None)
    assert classify_observations("ipv4-addr", ["inetnum", "ip_address"], value="192.0.2.10")[0] == "excluded"


def test_shared_infrastructure_is_excluded():
    status, reason = classify_observations(
        "ipv4-addr", ["contacted_ips[0].ip"],
        attributes={"is_shared_infrastructure": True, "exclusion_reason": "Cloudflare shared range."},
        value="104.21.9.123",
    )
    assert status == "excluded"
    assert "Cloudflare" in reason


def test_missing_context_is_unverified():
    assert classify_observations("domain-name", []) == (
        "unverified", "No linked extraction field path is available; manual review required."
    )


def test_qualifier_preserves_existing_triage_and_alert_records(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)

    changed, total, counts = qualify_alerts(db)
    assert changed == 7
    assert total == 7
    assert counts == {"eligible": 2, "excluded": 4, "unverified": 1}

    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT status,triaged_at_utc,triaged_by,resolution_note,eligibility FROM alert_records WHERE alert_id='a-range'").fetchone()
        assert row == ("triaged", "2026-09-30T01:00:00Z", "local-analyst", "Old reason", "excluded")

    assert qualify_alerts(db)[0] == 0


def test_requalifier_reactivates_alert_when_node_returns_active(tmp_path):
    db = tmp_path / "intel.db"
    make_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE infrastructure_nodes ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'active'")
        conn.execute("ALTER TABLE alert_records ADD COLUMN eligibility TEXT NOT NULL DEFAULT 'unverified'")
        conn.execute("ALTER TABLE alert_records ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'retired'")
        conn.execute("UPDATE alert_records SET eligibility='excluded',lifecycle_status='retired' WHERE alert_id='a-host'")
    changed, total, counts = qualify_alerts(db)
    assert changed >= 1
    with sqlite3.connect(db) as conn:
        state = conn.execute("SELECT eligibility,lifecycle_status FROM alert_records WHERE alert_id='a-host'").fetchone()
    assert state == ("eligible", "active")
