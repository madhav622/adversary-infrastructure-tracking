from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path

from extract_entities import ensure_lifecycle_schema

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"
LOG = ROOT / "logs" / "build_candidate_edges.log"
ALLOWED = ("S001", "S002", "S003", "S004")
RELATION = "co-observed-in-evidence"
CONFIDENCE = 0.2


def build_candidate_edges(db_path: Path) -> tuple[int, int]:
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        required = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = {
            "infrastructure_nodes", "seed_anchors",
            "evidence_records", "entity_observations",
            "infrastructure_edges",
        } - required
        if missing:
            raise ValueError(f"Missing required tables: {sorted(missing)}")

        ensure_lifecycle_schema(conn)
        node_states = {}
        node_columns = {row[1] for row in conn.execute("PRAGMA table_info(infrastructure_nodes)")}
        attributes_expr = "attributes_json" if "attributes_json" in node_columns else "'{}'"
        for node_id, lifecycle, attributes_json in conn.execute(
            f"SELECT node_id,lifecycle_status,{attributes_expr} FROM infrastructure_nodes"
        ):
            try:
                attributes = json.loads(attributes_json or "{}")
            except (TypeError, json.JSONDecodeError):
                attributes = {}
            node_states[node_id] = (lifecycle, attributes)

        rows = conn.execute("""
            SELECT e.evidence_id, e.seed_id, e.raw_file_path,
                   e.observed_at_utc, s.node_id, o.node_id, o.field_path
            FROM evidence_records e
            JOIN seed_anchors s ON s.seed_id = e.seed_id
            JOIN entity_observations o ON o.evidence_id = e.evidence_id
            WHERE e.seed_id IN ('S001','S002','S003','S004')
            ORDER BY e.seed_id, e.evidence_id, o.node_id, o.field_path
        """).fetchall()

        groups = {}
        for evidence_id, seed_id, file_path, observed, source_node, target_node, field in rows:
            if seed_id not in ALLOWED:
                raise ValueError(f"Out-of-scope seed: {seed_id}")
            if source_node == target_node:
                continue
            node_lifecycle, node_attributes = node_states.get(
                target_node, ("retired", {})
            )
            if node_lifecycle != "active" or node_attributes.get("is_shared_infrastructure"):
                continue

            key = (source_node, target_node, evidence_id)
            group = groups.setdefault(key, {
                "seed_id": seed_id,
                "file_path": file_path or "unknown",
                "observed": observed,
                "fields": set(),
            })
            if field:
                group["fields"].add(field)

        inserted = 0
        with conn:
            for (source, target, evidence_id), details in groups.items():
                edge_id = "relationship--" + hashlib.sha256(
                    "|".join((source, target, RELATION, evidence_id)).encode()
                ).hexdigest()

                fields = ", ".join(sorted(details["fields"])) or "unspecified"
                rationale = (
                    "Weak heuristic candidate: seed endpoint and observable "
                    "were extracted from the same passive evidence record. "
                    "This is not proof of direct connectivity, common control, "
                    "or actor attribution. "
                    f"Seed: {details['seed_id']}; "
                    f"raw file: {details['file_path']}; "
                    f"extracted field paths: {fields}. "
                    "Confidence 0.2 is a rule score, not a probability."
                )

                cursor = conn.execute("""
                    INSERT OR IGNORE INTO infrastructure_edges
                    (edge_id, source_node_id, target_node_id,
                     relationship_type, first_seen_utc, last_seen_utc,
                     confidence, evidence_id, status, rationale,
                     lifecycle_status, retirement_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'candidate', ?, 'active', NULL)
                """, (
                    edge_id, source, target, RELATION,
                    details["observed"], details["observed"],
                    CONFIDENCE, evidence_id, rationale,
                ))
                inserted += cursor.rowcount
                if cursor.rowcount == 0:
                    conn.execute("""
                        UPDATE infrastructure_edges
                        SET lifecycle_status='active',retirement_reason=NULL
                        WHERE edge_id=? AND lifecycle_status='retired'
                          AND (retirement_reason LIKE 'Retired because endpoint node was retired:%'
                               OR retirement_reason LIKE 'Retired because relationship no longer supported%')
                    """, (edge_id,))

            # Retire old candidate edges that are no longer supported by the
            # current field-aware evidence set, including shared infrastructure.
            existing_edges = conn.execute("""
                SELECT e.edge_id,e.source_node_id,e.target_node_id,e.evidence_id,
                       e.lifecycle_status,sa.seed_id
                FROM infrastructure_edges e
                LEFT JOIN seed_anchors sa ON sa.node_id=e.source_node_id
                WHERE e.relationship_type=? AND e.status='candidate'
            """, (RELATION,)).fetchall()
            current_keys = set(groups)
            for edge_id, source, target, evidence_id, lifecycle, seed_id in existing_edges:
                if lifecycle == 'retired' or seed_id not in ALLOWED:
                    continue
                if (source, target, evidence_id) in current_keys:
                    continue
                node_lifecycle, node_attributes = node_states.get(target, ("retired", {}))
                if node_lifecycle == "retired":
                    reason = "Retired because endpoint node was retired: target is not in the active extraction set."
                elif node_attributes.get("is_shared_infrastructure"):
                    reason = "Retired because relationship targets known shared infrastructure; not a unique host pivot."
                else:
                    reason = "Retired because relationship no longer supported by field-aware passive evidence extraction."
                conn.execute(
                    "UPDATE infrastructure_edges SET lifecycle_status='retired',retirement_reason=? WHERE edge_id=?",
                    (reason, edge_id),
                )

        total = conn.execute(
            "SELECT COUNT(*) FROM infrastructure_edges"
        ).fetchone()[0]
        return inserted, total
    finally:
        conn.close()


def main() -> int:
    logging.basicConfig(
        filename=str(LOG),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        inserted, total = build_candidate_edges(DB)
        logging.info("Candidate edges inserted=%d total=%d", inserted, total)
        print(f"Database: {DB}")
        print(f"New candidate edges: {inserted}")
        print(f"Total edges: {total}")
        print("Relationship: co-observed-in-evidence")
        print("All generated edges remain candidates.")
        return 0
    except Exception as exc:
        logging.exception("Candidate edge generation failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
