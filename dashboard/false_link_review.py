from pathlib import Path
import pandas as pd
from dashboard.data_access import DEFAULT_DB, read_query

ALLOWED = ("S001", "S002", "S003", "S004")


def load_false_link_candidates(
    database=DEFAULT_DB,
    seed_id=None,
    max_confidence=0.2,
):
    if not isinstance(max_confidence, (int, float)):
        raise ValueError("Maximum confidence must be numeric")
    if not 0 <= max_confidence <= 1:
        raise ValueError("Maximum confidence must be between 0 and 1")

    params = [max_confidence]
    seed_filter = ""
    if seed_id is not None:
        seed = str(seed_id).strip().upper()
        if seed not in ALLOWED:
            raise ValueError(f"Seed outside allowed scope: {seed}")
        seed_filter = " AND sa.seed_id = ?"
        params.append(seed)

    result = read_query(
        f"""
        SELECT
            e.edge_id,
            sa.seed_id,
            src.value AS seed_endpoint,
            target.node_id AS target_node_id,
            target.node_type AS target_type,
            target.value AS target,
            e.relationship_type,
            e.confidence,
            e.status,
            e.evidence_id,
            ev.source_name,
            ev.raw_file_path,
            e.first_seen_utc,
            e.last_seen_utc,
            (
                SELECT COUNT(DISTINCT sa2.seed_id)
                FROM infrastructure_edges e2
                JOIN seed_anchors sa2
                  ON sa2.node_id=e2.source_node_id
                WHERE e2.target_node_id=e.target_node_id
                  AND e2.status='candidate'
                  AND e2.relationship_type=e.relationship_type
                  AND sa2.seed_id IN ('S001','S002','S003','S004')
            ) AS seed_overlap,
            e.rationale
        FROM infrastructure_edges e
        JOIN seed_anchors sa ON sa.node_id=e.source_node_id
        JOIN infrastructure_nodes src ON src.node_id=e.source_node_id
        JOIN infrastructure_nodes target ON target.node_id=e.target_node_id
        JOIN evidence_records ev ON ev.evidence_id=e.evidence_id
        WHERE e.status='candidate'
          AND e.relationship_type='co-observed-in-evidence'
          AND e.confidence <= ?
          AND sa.seed_id IN ('S001','S002','S003','S004')
          {seed_filter}
        ORDER BY seed_overlap DESC, e.confidence ASC, e.edge_id
        """,
        tuple(params),
        database,
    )

    if not result.empty:
        result["review_hint"] = result["seed_overlap"].apply(
            lambda value: (
                "Repeated across seeds — inspect"
                if value > 1 else "Single-seed observation"
            )
        )
    return result
