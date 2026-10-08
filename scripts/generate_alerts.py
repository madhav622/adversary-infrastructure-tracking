from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from extract_entities import ensure_lifecycle_schema

ROOT = Path(__file__).resolve().parents[1]
DB_FILE = ROOT / "database" / "intel.db"
LOG_FILE = ROOT / "logs" / "generate_alerts.log"
SEEDS = ("S001", "S002", "S003", "S004")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def normalize_time(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def initialize_alert_schema(conn):
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_records (
            alert_id TEXT PRIMARY KEY,
            alert_type TEXT NOT NULL
                CHECK(alert_type = 'new_observable_in_dataset'),
            seed_id TEXT NOT NULL
                CHECK(seed_id IN ('S001','S002','S003','S004')),
            node_id TEXT NOT NULL
                REFERENCES infrastructure_nodes(node_id),
            cluster_id TEXT REFERENCES clusters(cluster_id),
            severity TEXT NOT NULL DEFAULT 'informational'
                CHECK(severity IN (
                    'informational','low','medium','high','critical'
                )),
            status TEXT NOT NULL DEFAULT 'new'
                CHECK(status IN (
                    'new','triaged','blocked','false_positive'
                )),
            first_observed_utc TEXT,
            last_observed_utc TEXT,
            created_at_utc TEXT NOT NULL,
            lead_time_days REAL
                CHECK(lead_time_days IS NULL OR lead_time_days >= 0),
            evidence_ids_json TEXT NOT NULL,
            sources_json TEXT NOT NULL,
            summary TEXT NOT NULL,
            rationale TEXT NOT NULL,
            triaged_at_utc TEXT,
            triaged_by TEXT,
            resolution_note TEXT,
            updated_at_utc TEXT NOT NULL,
            eligibility TEXT NOT NULL DEFAULT 'unverified'
                CHECK(eligibility IN ('eligible','excluded','unverified')),
            eligibility_reason TEXT,
            eligibility_updated_at_utc TEXT,
            lifecycle_status TEXT NOT NULL DEFAULT 'active'
                CHECK(lifecycle_status IN ('active','retired')),
            retirement_reason TEXT,
            UNIQUE(alert_type, seed_id, node_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_records_status
        ON alert_records(status, severity)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_records_seed
        ON alert_records(seed_id)
    """)
    ensure_lifecycle_schema(conn)
    conn.commit()


def cluster_for_seed(conn, seed_id):
    rows = conn.execute("""
        SELECT DISTINCT c.cluster_id
        FROM cluster_memberships cm
        JOIN clusters c ON c.cluster_id = cm.cluster_id
        JOIN seed_anchors sa ON sa.node_id = cm.node_id
        WHERE sa.seed_id = ?
          AND cm.membership_type = 'candidate-member'
        ORDER BY c.cluster_id
    """, (seed_id,)).fetchall()

    # Do not arbitrarily choose among multiple candidate clusters.
    if len(rows) == 1:
        return rows[0][0]
    return None


def generate_alerts(db_path=DB_FILE):
    if not Path(db_path).is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    new_count = 0
    updated_count = 0

    with sqlite3.connect(str(db_path), timeout=30) as conn:
        initialize_alert_schema(conn)

        node_columns = {row[1] for row in conn.execute("PRAGMA table_info(infrastructure_nodes)")}
        attributes_expr = "n.attributes_json" if "attributes_json" in node_columns else "'{}'"
        observations = conn.execute(f"""
            SELECT
                er.seed_id, sa.node_id AS seed_node_id, eo.node_id,
                n.node_type, n.value, er.evidence_id, er.source_name,
                er.observed_at_utc, {attributes_expr}, n.lifecycle_status
            FROM entity_observations eo
            JOIN evidence_records er ON er.evidence_id = eo.evidence_id
            JOIN seed_anchors sa ON sa.seed_id = er.seed_id
            JOIN infrastructure_nodes n ON n.node_id = eo.node_id
            WHERE er.seed_id IN ('S001','S002','S003','S004')
              AND eo.node_id <> sa.node_id
              AND n.lifecycle_status='active'
            ORDER BY er.seed_id, eo.node_id, er.evidence_id
        """).fetchall()

        grouped = {}
        for (
            seed_id, seed_node_id, node_id, node_type, value,
            evidence_id, source_name, observed_at, attributes_json,
            node_lifecycle
        ) in observations:
            try:
                node_attributes = json.loads(attributes_json or "{}")
            except (TypeError, json.JSONDecodeError):
                node_attributes = {}
            if node_attributes.get("is_shared_infrastructure"):
                continue
            key = (seed_id, node_id)
            item = grouped.setdefault(key, {
                "seed_node_id": seed_node_id,
                "node_type": node_type,
                "value": value,
                "evidence_ids": set(),
                "sources": set(),
                "observed_times": set(),
            })
            item["evidence_ids"].add(evidence_id)
            if source_name:
                item["sources"].add(source_name)
            timestamp = normalize_time(observed_at)
            if timestamp:
                item["observed_times"].add(timestamp)

        with conn:
            for (seed_id, node_id), item in sorted(grouped.items()):
                alert_type = "new_observable_in_dataset"
                alert_id = "alert--" + hashlib.sha256(
                    f"{alert_type}|{seed_id}|{node_id}".encode()
                ).hexdigest()

                evidence_ids = sorted(item["evidence_ids"])
                sources = sorted(item["sources"])
                times = sorted(item["observed_times"])
                first_seen = times[0] if times else None
                last_seen = times[-1] if times else None

                cluster_id = cluster_for_seed(conn, seed_id)
                created_at = utc_now()
                summary = (
                    f"Observable {item['value']} found in the current "
                    f"evidence set for {seed_id}."
                )
                rationale = (
                    "This alert records an observable present in the "
                    "project's imported passive evidence. It does not "
                    "mean the infrastructure is globally new or confirmed "
                    "malicious. Initial severity is informational. "
                    "Cluster association is populated only when exactly "
                    "one candidate cluster membership is available. "
                    "Lead time is unknown because no verified outcome "
                    "timestamp is available."
                )

                existing = conn.execute("""
                    SELECT evidence_ids_json, sources_json,
                           first_observed_utc, last_observed_utc,
                           cluster_id
                    FROM alert_records
                    WHERE alert_id = ?
                """, (alert_id,)).fetchone()

                if existing is None:
                    conn.execute("""
                        INSERT INTO alert_records (
                            alert_id, alert_type, seed_id, node_id,
                            cluster_id, severity, status,
                            first_observed_utc, last_observed_utc,
                            created_at_utc, lead_time_days,
                            evidence_ids_json, sources_json,
                            summary, rationale, updated_at_utc,
                            lifecycle_status, retirement_reason
                        ) VALUES (
                            ?, ?, ?, ?, ?, 'informational', 'new',
                            ?, ?, ?, NULL, ?, ?, ?, ?, ?, 'active', NULL
                        )
                    """, (
                        alert_id, alert_type, seed_id, node_id,
                        cluster_id, first_seen, last_seen, created_at,
                        json.dumps(evidence_ids),
                        json.dumps(sources),
                        summary, rationale, created_at,
                    ))
                    new_count += 1
                else:
                    old_evidence = set(json.loads(existing[0]))
                    old_sources = set(json.loads(existing[1]))
                    merged_evidence = sorted(old_evidence | set(evidence_ids))
                    merged_sources = sorted(old_sources | set(sources))

                    all_times = sorted(
                        t for t in (existing[2], existing[3], first_seen, last_seen)
                        if t
                    )
                    merged_first = all_times[0] if all_times else None
                    merged_last = all_times[-1] if all_times else None

                    old_cluster = existing[4]
                    if old_cluster is None:
                        old_cluster = cluster_id

                    changed = (
                        merged_evidence != json.loads(existing[0])
                        or merged_sources != json.loads(existing[1])
                        or merged_first != existing[2]
                        or merged_last != existing[3]
                        or old_cluster != existing[4]
                    )

                    if changed:
                        conn.execute("""
                            UPDATE alert_records
                            SET evidence_ids_json = ?,
                                sources_json = ?,
                                first_observed_utc = ?,
                                last_observed_utc = ?,
                                cluster_id = ?,
                                updated_at_utc = ?,
                                lifecycle_status='active',
                                retirement_reason=NULL
                            WHERE alert_id = ?
                        """, (
                            json.dumps(merged_evidence),
                            json.dumps(merged_sources),
                            merged_first, merged_last, old_cluster,
                            utc_now(), alert_id,
                        ))
                        updated_count += 1

        total = conn.execute(
            "SELECT COUNT(*) FROM alert_records"
        ).fetchone()[0]
        status_counts = dict(conn.execute("""
            SELECT status, COUNT(*)
            FROM alert_records
            GROUP BY status
        """).fetchall())

    return new_count, updated_count, total, status_counts


def main():
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        new_count, updated, total, statuses = generate_alerts()
        logging.info(
            "Alert generation complete: new=%d updated=%d total=%d",
            new_count, updated, total,
        )
        print(f"Database: {DB_FILE}")
        print(f"New alerts: {new_count}")
        print(f"Updated existing alerts: {updated}")
        print(f"Total alerts: {total}")
        for status in ("new", "triaged", "blocked", "false_positive"):
            print(f"{status}: {statuses.get(status, 0)}")
        print("Initial severity: informational")
        print("Lead time: not calculated (no outcome timestamp)")
        print("Scope: S001-S004; no fabricated alerts")
        return 0
    except Exception as exc:
        logging.exception("Alert generation failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
