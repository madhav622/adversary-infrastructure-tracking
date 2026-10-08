from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dashboard.data_access import DEFAULT_DB, read_query

ALLOWED_SEEDS = ("S001", "S002", "S003", "S004")
STATUSES = ("new", "triaged", "blocked", "false_positive")
SEVERITIES = ("informational", "low", "medium", "high", "critical")

TRANSITIONS = {
    "new": ("new", "triaged", "false_positive"),
    "triaged": ("triaged", "blocked", "false_positive"),
    "blocked": ("blocked", "triaged", "false_positive"),
    "false_positive": ("false_positive", "triaged"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def allowed_statuses(current: str) -> tuple[str, ...]:
    if current not in TRANSITIONS:
        raise ValueError("Unknown current alert status")
    return TRANSITIONS[current]


def get_alerts(
    database=DEFAULT_DB,
    status=None,
    severity=None,
    seed_id=None,
    limit=500,
):
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 2000:
        raise ValueError("Limit must be between 1 and 2000")

    filters = [
        "a.seed_id IN ('S001','S002','S003','S004')"
    ]
    params = []

    if status is not None:
        if status not in STATUSES:
            raise ValueError("Invalid alert status")
        filters.append("a.status = ?")
        params.append(status)

    if severity is not None:
        if severity not in SEVERITIES:
            raise ValueError("Invalid alert severity")
        filters.append("a.severity = ?")
        params.append(severity)

    if seed_id is not None:
        seed = str(seed_id).strip().upper()
        if seed not in ALLOWED_SEEDS:
            raise ValueError("Seed outside allowed scope")
        filters.append("a.seed_id = ?")
        params.append(seed)

    params.append(limit)

    sql = """
        SELECT
            a.alert_id, a.alert_type, a.seed_id, a.node_id,
            n.node_type, n.value AS observable, a.cluster_id,
            a.severity, a.status, a.first_observed_utc,
            a.last_observed_utc, a.created_at_utc, a.lead_time_days,
            a.evidence_ids_json, a.sources_json, a.summary,
            a.rationale, a.triaged_at_utc, a.triaged_by,
            a.resolution_note, a.updated_at_utc, a.eligibility, a.eligibility_reason, a.eligibility_updated_at_utc
        FROM alert_records a
        JOIN infrastructure_nodes n ON n.node_id = a.node_id
        WHERE """ + " AND ".join(filters) + """
        ORDER BY
            CASE a.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END,
            a.created_at_utc DESC,
            a.alert_id
        LIMIT ?
    """
    return read_query(sql, tuple(params), database)


def ensure_history_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_triage_history (
            history_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL
                REFERENCES alert_records(alert_id),
            previous_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            previous_severity TEXT NOT NULL,
            new_severity TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            reason TEXT NOT NULL,
            changed_at_utc TEXT NOT NULL
        )
    """)


def get_alert_history(alert_id, database=DEFAULT_DB):
    alert_id = str(alert_id).strip()
    if not alert_id:
        raise ValueError("Alert ID is required")

    with sqlite3.connect(str(database), timeout=30) as conn:
        ensure_history_table(conn)
        conn.commit()

    return read_query(
        """
        SELECT previous_status, new_status,
               previous_severity, new_severity,
               reviewer, reason, changed_at_utc
        FROM alert_triage_history
        WHERE alert_id = ?
        ORDER BY changed_at_utc DESC, history_id DESC
        LIMIT 50
        """,
        (alert_id,),
        database,
    )


def update_alert(
    alert_id,
    new_status,
    new_severity,
    reviewer,
    reason,
    database=DEFAULT_DB,
):
    alert_id = str(alert_id).strip()
    reviewer = str(reviewer).strip()
    reason = str(reason).strip()

    if not alert_id or len(alert_id) > 256:
        raise ValueError("Invalid alert ID")
    if new_status not in STATUSES:
        raise ValueError("Invalid alert status")
    if new_severity not in SEVERITIES:
        raise ValueError("Invalid alert severity")
    if not 1 <= len(reviewer) <= 80:
        raise ValueError("Reviewer label must contain 1-80 characters")
    if not 5 <= len(reason) <= 2000:
        raise ValueError("Reason must contain 5-2000 characters")

    with sqlite3.connect(str(database), timeout=30) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        ensure_history_table(conn)
        conn.commit()

        conn.execute("BEGIN IMMEDIATE")
        try:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(alert_records)")}
            eligibility_expr = "eligibility" if "eligibility" in columns else "'unverified'"
            lifecycle_expr = "lifecycle_status" if "lifecycle_status" in columns else "'active'"
            row = conn.execute(f"""
                SELECT status, severity, triaged_at_utc, triaged_by,
                       {eligibility_expr}, {lifecycle_expr}
                FROM alert_records
                WHERE alert_id = ?
                  AND seed_id IN ('S001','S002','S003','S004')
            """, (alert_id,)).fetchone()

            if row is None:
                raise ValueError("Alert does not exist in allowed scope")

            old_status, old_severity, old_triaged_at, old_triaged_by, eligibility, lifecycle_status = row
            if eligibility != "eligible" or lifecycle_status == "retired":
                raise ValueError(
                    f"Triage disabled: alert is {eligibility} and lifecycle is {lifecycle_status}."
                )

            if new_status not in allowed_statuses(old_status):
                raise ValueError(
                    f"Invalid transition: {old_status} -> {new_status}"
                )

            changed_at = utc_now()
            triaged_at = old_triaged_at
            triaged_by = old_triaged_by

            if new_status != "new":
                if old_status != new_status or not triaged_at:
                    triaged_at = changed_at
                    triaged_by = reviewer

            event_data = "|".join((
                alert_id, changed_at, old_status, new_status,
                old_severity, new_severity, reviewer, reason,
            ))
            history_id = "alert-review--" + hashlib.sha256(
                event_data.encode("utf-8")
            ).hexdigest()

            conn.execute("""
                UPDATE alert_records
                SET status = ?, severity = ?,
                    triaged_at_utc = ?, triaged_by = ?,
                    resolution_note = ?, updated_at_utc = ?
                WHERE alert_id = ?
            """, (
                new_status, new_severity, triaged_at, triaged_by,
                reason, changed_at, alert_id,
            ))

            conn.execute("""
                INSERT INTO alert_triage_history (
                    history_id, alert_id, previous_status, new_status,
                    previous_severity, new_severity, reviewer, reason,
                    changed_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                history_id, alert_id, old_status, new_status,
                old_severity, new_severity, reviewer, reason,
                changed_at,
            ))
            conn.commit()
            return {
                "alert_id": alert_id,
                "status": new_status,
                "severity": new_severity,
                "reviewer": reviewer,
                "changed_at_utc": changed_at,
            }
        except Exception:
            conn.rollback()
            raise
