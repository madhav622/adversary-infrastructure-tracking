from pathlib import Path

import pandas as pd

from dashboard.data_access import DEFAULT_DB, read_query

ALLOWED_SEEDS = ("S001", "S002", "S003", "S004")


def _scope(seed_id):
    if seed_id is None:
        return (
            "seed_id IN ('S001','S002','S003','S004')",
            (),
        )
    seed = str(seed_id).strip().upper()
    if seed not in ALLOWED_SEEDS:
        raise ValueError(f"Seed outside allowed scope: {seed}")
    return "seed_id = ?", (seed,)


def get_source_quality(database=DEFAULT_DB, seed_id=None):
    where, params = _scope(seed_id)
    return read_query(
        f"""
        SELECT
            source_name,
            COUNT(*) AS evidence_records,
            COUNT(DISTINCT seed_id) AS seed_coverage,
            SUM(
                CASE WHEN raw_sha256 IS NOT NULL
                     AND LENGTH(raw_sha256) = 64
                     THEN 1 ELSE 0 END
            ) AS sha256_present_records,
            SUM(
                CASE WHEN source_reference IS NOT NULL
                     AND LENGTH(TRIM(source_reference)) > 0
                     THEN 1 ELSE 0 END
            ) AS reference_records,
            SUM(
                CASE WHEN observed_at_utc IS NOT NULL
                     AND LENGTH(TRIM(observed_at_utc)) > 0
                     THEN 1 ELSE 0 END
            ) AS timestamp_records,
            MIN(observed_at_utc) AS first_observed_utc,
            MAX(observed_at_utc) AS last_observed_utc
        FROM evidence_records
        WHERE {where}
        GROUP BY source_name
        ORDER BY evidence_records DESC, source_name
        """,
        params,
        database,
    )


def get_source_coverage(database=DEFAULT_DB, seed_id=None):
    where, params = _scope(seed_id)
    return read_query(
        f"""
        SELECT
            seed_id,
            source_name,
            COUNT(*) AS evidence_records,
            SUM(
                CASE WHEN raw_sha256 IS NOT NULL
                     AND LENGTH(raw_sha256) = 64
                     THEN 1 ELSE 0 END
            ) AS sha256_present_records
        FROM evidence_records
        WHERE {where}
        GROUP BY seed_id, source_name
        ORDER BY seed_id, source_name
        """,
        params,
        database,
    )
