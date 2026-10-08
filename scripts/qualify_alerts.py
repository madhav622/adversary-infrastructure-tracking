from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from entity_validation import (
    domain_validation_reason,
    load_shared_infrastructure,
    shared_infrastructure_match,
    validate_public_ip,
)
from extract_entities import ensure_lifecycle_schema

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"
LOG = ROOT / "logs" / "qualify_alerts.log"

RANGE_FIELDS = {
    "inetnum", "cidr", "netblock", "netblocks", "subnet", "subnet_range",
    "network_range", "ip_range", "ipv4_range", "ipv6_range",
    "address_range", "start_ip", "end_ip", "start_address", "end_address",
    "broadcast_address", "network_address", "route", "network",
}
METADATA_FIELDS = {
    "vendor", "vendors", "engine", "engines", "popular_threat_label",
    "threat_label", "malware_label", "malware_family", "threat_family",
    "detection", "detections", "family_labels", "threat_categories",
}
FILENAME_FIELDS = {"filename", "file_name", "basename"}
IP_TYPES = {"ipv4-addr", "ipv6-addr"}


def utc_now():
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def segments(field_path):
    return [
        re.sub(r"[^a-z0-9]+", "_", part.casefold()).strip("_")
        for part in re.split(r"[.\[\]]+", str(field_path))
        if part.strip() and not part.isdigit()
    ]


def classify_observations(
    node_type,
    field_paths,
    attributes=None,
    value=None,
    lifecycle_status="active",
    shared_entries=None,
):
    attributes = attributes if isinstance(attributes, dict) else {}
    if lifecycle_status == "retired" or attributes.get("lifecycle_status") == "retired":
        reason = attributes.get("exclusion_reason") or "Node is retired from the active extraction set."
        return "excluded", str(reason)

    if attributes.get("is_shared_infrastructure"):
        reason = attributes.get("exclusion_reason") or "Known shared infrastructure; not eligible for actionable alerting."
        return "excluded", str(reason)

    paths = sorted({
        str(path).strip()
        for path in (field_paths or [])
        if path is not None and str(path).strip()
    })
    if not paths:
        return (
            "unverified",
            "No linked extraction field path is available; manual review required.",
        )

    eligible_paths = []
    excluded_metadata = set()
    excluded_ranges = set()
    excluded_filenames = set()

    for path in paths:
        parts = segments(path)
        if set(parts).intersection(METADATA_FIELDS):
            excluded_metadata.add(path)
            continue
        if set(parts).intersection(FILENAME_FIELDS):
            excluded_filenames.add(path)
            continue
        if node_type in IP_TYPES and set(parts).intersection(RANGE_FIELDS):
            excluded_ranges.add(path)
            continue
        eligible_paths.append(path)

    if eligible_paths:
        if node_type in IP_TYPES and value is not None:
            normalized, ip_reason = validate_public_ip(value)
            if ip_reason:
                return "excluded", ip_reason
            shared = shared_infrastructure_match(
                normalized,
                shared_entries if shared_entries is not None else load_shared_infrastructure(),
            )
            if shared:
                return "excluded", shared["reason"]
        if node_type == "domain-name" and value is not None:
            domain_reason = domain_validation_reason(value)
            if domain_reason:
                return "excluded", domain_reason
        return "eligible", None

    reasons = []
    if excluded_ranges:
        reasons.append(
            "IP values found only in network allocation/range fields: "
            + ", ".join(sorted(excluded_ranges))
        )
    if excluded_metadata:
        reasons.append(
            "Values found only in non-infrastructure metadata fields: "
            + ", ".join(sorted(excluded_metadata))
        )
    if excluded_filenames:
        reasons.append(
            "Values found only in filename fields: "
            + ", ".join(sorted(excluded_filenames))
        )

    if reasons:
        return "excluded", "; ".join(reasons) + ". Not eligible for the actionable alert queue."
    return "unverified", "Observation context could not be qualified."


def _columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def qualify_alerts(db_path=DB):
    db_path = Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    shared_entries = load_shared_infrastructure()
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        tables = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {
            "alert_records", "infrastructure_nodes",
            "entity_observations", "evidence_records",
        }
        missing = required - tables
        if missing:
            raise ValueError(f"Missing tables: {sorted(missing)}")

        ensure_lifecycle_schema(conn)
        node_columns = _columns(conn, "infrastructure_nodes")
        attributes_expr = "n.attributes_json" if "attributes_json" in node_columns else "'{}'"
        node_lifecycle_expr = "n.lifecycle_status" if "lifecycle_status" in node_columns else "'active'"

        alerts = conn.execute(f"""
            SELECT a.alert_id,a.seed_id,a.node_id,n.node_type,
                   {attributes_expr},{node_lifecycle_expr},
                   a.eligibility,a.eligibility_reason,a.lifecycle_status
            FROM alert_records a
            LEFT JOIN infrastructure_nodes n ON n.node_id=a.node_id
            WHERE a.seed_id IN ('S001','S002','S003','S004')
            ORDER BY a.alert_id
        """).fetchall()

        changed = 0
        with conn:
            for (
                alert_id, seed_id, node_id, node_type, attributes_json,
                node_lifecycle, old_status, old_reason, alert_lifecycle,
            ) in alerts:
                if node_type is None:
                    status = "excluded"
                    reason = "Associated infrastructure node is missing; alert is retired from the actionable set."
                    node_lifecycle = "retired"
                else:
                    try:
                        attributes = json.loads(attributes_json or "{}")
                        if not isinstance(attributes, dict):
                            attributes = {}
                    except (TypeError, ValueError):
                        attributes = {}
                    paths = conn.execute("""
                        SELECT DISTINCT eo.field_path
                        FROM entity_observations eo
                        JOIN evidence_records ev ON ev.evidence_id=eo.evidence_id
                        WHERE ev.seed_id=? AND eo.node_id=?
                    """, (seed_id, node_id)).fetchall()
                    status, reason = classify_observations(
                        node_type,
                        [row[0] for row in paths],
                        attributes=attributes,
                        value=conn.execute(
                            "SELECT value FROM infrastructure_nodes WHERE node_id=?",
                            (node_id,),
                        ).fetchone()[0],
                        lifecycle_status=node_lifecycle,
                        shared_entries=shared_entries,
                    )

                new_lifecycle = "retired" if node_lifecycle == "retired" else "active"
                if node_lifecycle == "retired":
                    status = "excluded"
                    reason = reason or "Associated infrastructure node is retired."
                    new_lifecycle = "retired"
                if status != old_status or reason != old_reason or new_lifecycle != alert_lifecycle:
                    conn.execute("""
                        UPDATE alert_records
                        SET eligibility=?,eligibility_reason=?,
                            eligibility_updated_at_utc=?,lifecycle_status=?,
                            retirement_reason=CASE WHEN ?='retired' THEN COALESCE(retirement_reason,?) ELSE retirement_reason END
                        WHERE alert_id=?
                    """, (
                        status, reason, utc_now(), new_lifecycle,
                        new_lifecycle, reason, alert_id,
                    ))
                    changed += 1

        counts = dict(conn.execute("""
            SELECT eligibility,COUNT(*) FROM alert_records
            WHERE seed_id IN ('S001','S002','S003','S004')
            GROUP BY eligibility
        """).fetchall())
        total = sum(counts.values())

    return changed, total, counts


def main():
    logging.basicConfig(
        filename=str(LOG), level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8", force=True,
    )
    try:
        changed, total, counts = qualify_alerts()
        logging.info("Alert qualification changed=%d total=%d", changed, total)
        print(f"Database: {DB}")
        print(f"Eligibility classifications updated: {changed}")
        print(f"Total alert records retained: {total}")
        for key in ("eligible", "excluded", "unverified"):
            print(f"{key}: {counts.get(key, 0)}")
        print("Excluded/retired alerts cannot be triaged through the backend.")
        print("Alert status, severity and audit history are preserved.")
        return 0
    except Exception as exc:
        logging.exception("Alert qualification failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
