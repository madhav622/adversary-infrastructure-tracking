from pathlib import Path
import pandas as pd
from dashboard.data_access import DEFAULT_DB, read_query

ALLOWED_SEEDS = ("S001", "S002", "S003", "S004")


def find_seed(query: str, database: Path = DEFAULT_DB) -> pd.DataFrame:
    term = query.strip()
    if not term:
        return pd.DataFrame()

    return read_query(
        """
        SELECT sa.seed_id, n.node_id, n.value AS endpoint
        FROM seed_anchors sa
        JOIN infrastructure_nodes n ON n.node_id = sa.node_id
        WHERE sa.seed_id IN ('S001','S002','S003','S004')
          AND (UPPER(sa.seed_id) = ? OR LOWER(n.value) = ?)
        ORDER BY sa.seed_id
        """,
        (term.upper(), term.casefold()),
        database,
    )


def find_pivots(seed_id: str, database: Path = DEFAULT_DB) -> pd.DataFrame:
    seed = seed_id.strip().upper()
    if seed not in ALLOWED_SEEDS:
        raise ValueError(f"Seed is outside the allowed scope: {seed}")

    return read_query(
        """
        SELECT
            e.edge_id,
            e.relationship_type,
            e.status,
            e.confidence AS pivot_strength,
            e.first_seen_utc,
            e.last_seen_utc,
            e.evidence_id,
            target.node_type,
            target.value,
            evidence.source_name,
            evidence.raw_file_path,
            evidence.raw_sha256,
            e.rationale
        FROM infrastructure_edges e
        JOIN seed_anchors sa ON sa.node_id = e.source_node_id
        JOIN infrastructure_nodes target
            ON target.node_id = e.target_node_id
        JOIN evidence_records evidence
            ON evidence.evidence_id = e.evidence_id
        WHERE sa.seed_id = ?
          AND e.relationship_type = 'co-observed-in-evidence'
          AND e.status IN ('candidate','confirmed')
        ORDER BY target.node_type, target.value, e.evidence_id
        """,
        (seed,),
        database,
    )
