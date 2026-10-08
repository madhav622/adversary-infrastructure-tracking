from __future__ import annotations

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"
JSON_OUT = ROOT / "exports" / "alerts_export.json"
CSV_OUT = ROOT / "exports" / "alerts_export.csv"
LOG = ROOT / "logs" / "export_alerts.log"

ALLOWED = ("S001", "S002", "S003", "S004")

FIELDS = [
    "alert_id", "alert_type", "seed_id", "node_id",
    "node_type", "observable", "cluster_id", "severity",
    "status", "eligibility", "eligibility_reason",
    "first_observed_utc", "last_observed_utc",
    "created_at_utc", "lead_time_days",
    "evidence_ids", "sources", "summary", "rationale",
    "triaged_at_utc", "triaged_by", "resolution_note",
    "updated_at_utc", "triage_history",
]


def now_utc():
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def parse_array(value, field):
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON in {field}") from exc
    if not isinstance(parsed, list):
        raise ValueError(f"{field} must contain a JSON array")
    return parsed


def export_alerts(db_path=DB, json_path=JSON_OUT, csv_path=CSV_OUT):
    db_path = Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    uri = db_path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=30) as conn:
        columns = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(alert_records)"
            )
        }
        required = {
            "alert_id", "alert_type", "seed_id", "node_id",
            "cluster_id", "severity", "status", "eligibility",
            "eligibility_reason", "first_observed_utc",
            "last_observed_utc", "created_at_utc", "lead_time_days",
            "evidence_ids_json", "sources_json", "summary",
            "rationale", "triaged_at_utc", "triaged_by",
            "resolution_note", "updated_at_utc",
        }
        missing = required - columns
        if missing:
            raise ValueError(
                "Alert schema incomplete; missing: " + ", ".join(sorted(missing))
            )

        node_columns = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(infrastructure_nodes)"
            )
        }
        if not {"node_id", "node_type", "value"} <= node_columns:
            raise ValueError("Infrastructure node schema is incomplete")

        rows = conn.execute("""
            SELECT a.alert_id, a.alert_type, a.seed_id, a.node_id,
                   n.node_type, n.value, a.cluster_id, a.severity,
                   a.status, a.eligibility, a.eligibility_reason,
                   a.first_observed_utc, a.last_observed_utc,
                   a.created_at_utc, a.lead_time_days,
                   a.evidence_ids_json, a.sources_json,
                   a.summary, a.rationale, a.triaged_at_utc,
                   a.triaged_by, a.resolution_note, a.updated_at_utc
            FROM alert_records a
            JOIN infrastructure_nodes n ON n.node_id=a.node_id
            WHERE a.seed_id IN ('S001','S002','S003','S004')
            ORDER BY a.created_at_utc, a.alert_id
        """).fetchall()

        history_table = conn.execute("""
            SELECT 1 FROM sqlite_master
            WHERE type='table' AND name='alert_triage_history'
        """).fetchone()

        history_by_alert = {}
        if history_table:
            history_rows = conn.execute("""
                SELECT alert_id, previous_status, new_status,
                       previous_severity, new_severity,
                       reviewer, reason, changed_at_utc
                FROM alert_triage_history
                ORDER BY changed_at_utc, history_id
            """).fetchall()
            for row in history_rows:
                alert_id = row[0]
                history_by_alert.setdefault(alert_id, []).append({
                    "previous_status": row[1],
                    "new_status": row[2],
                    "previous_severity": row[3],
                    "new_severity": row[4],
                    "reviewer": row[5],
                    "reason": row[6],
                    "changed_at_utc": row[7],
                })

    records = []
    for row in rows:
        (
            alert_id, alert_type, seed_id, node_id, node_type,
            observable, cluster_id, severity, status, eligibility,
            eligibility_reason, first_observed, last_observed,
            created, lead_time, evidence_json, sources_json,
            summary, rationale, triaged_at, triaged_by,
            resolution_note, updated,
        ) = row

        if seed_id not in ALLOWED:
            raise ValueError(f"Out-of-scope alert: {seed_id}")

        record = {
            "alert_id": alert_id,
            "alert_type": alert_type,
            "seed_id": seed_id,
            "node_id": node_id,
            "node_type": node_type,
            "observable": observable,
            "cluster_id": cluster_id,
            "severity": severity,
            "status": status,
            "eligibility": eligibility,
            "eligibility_reason": eligibility_reason,
            "first_observed_utc": first_observed,
            "last_observed_utc": last_observed,
            "created_at_utc": created,
            "lead_time_days": lead_time,
            "evidence_ids": parse_array(evidence_json, "evidence_ids_json"),
            "sources": parse_array(sources_json, "sources_json"),
            "summary": summary,
            "rationale": rationale,
            "triaged_at_utc": triaged_at,
            "triaged_by": triaged_by,
            "resolution_note": resolution_note,
            "updated_at_utc": updated,
            "triage_history": history_by_alert.get(alert_id, []),
        }
        records.append(record)

    document = {
        "schema_version": "1.0",
        "feed_name": "AITC Alert Export",
        "generated_at_utc": now_utc(),
        "scope": list(ALLOWED),
        "alert_count": len(records),
        "alerts": records,
        "blocking_policy": (
            "Export is informational. Status 'blocked' does not "
            "perform an infrastructure blocking action."
        ),
    }

    json_text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    buffer = StringIO(newline="")
    writer = csv.DictWriter(
        buffer, fieldnames=FIELDS, extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for record in records:
        row = record.copy()
        row["evidence_ids"] = json.dumps(row["evidence_ids"])
        row["sources"] = json.dumps(row["sources"])
        row["triage_history"] = json.dumps(
            row["triage_history"], ensure_ascii=False
        )
        writer.writerow(row)

    def atomic_write(path, content):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".tmp")
        temp.write_text(content, encoding="utf-8")
        temp.replace(path)

    atomic_write(json_path, json_text)
    atomic_write(csv_path, buffer.getvalue())
    return len(records)


def main():
    logging.basicConfig(
        filename=str(LOG),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        count = export_alerts()
        logging.info("Exported %d alert records", count)
        print(f"JSON: {JSON_OUT}")
        print(f"CSV: {CSV_OUT}")
        print(f"Exported alerts: {count}")
        print("Scope: S001-S004")
        print("Triage history included when available.")
        return 0
    except Exception as exc:
        logging.exception("Alert export failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
