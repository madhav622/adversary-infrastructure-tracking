from __future__ import annotations

import csv
import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_FILE = ROOT / "database" / "intel.db"
LOG_FILE = ROOT / "logs" / "clustering.log"
REPORT_FILE = ROOT / "exports" / "cluster_pair_scores.csv"

SEEDS = ("S001", "S002", "S003", "S004")
ALGORITHM = "shared-observable-pairwise-v1"
THRESHOLD = 0.50

# Heuristic weights; these are not statistical probabilities.
WEIGHTS = {
    "domain-name": 0.35,
    "certificate-fingerprint": 0.65,
    "file-hash-sha256": 0.70,
    "file-hash-sha1": 0.55,
    "file-hash-md5": 0.40,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def score_shared_observables(shared: list[dict]) -> float:
    # Each distinct observable contributes at most once.
    remaining = 1.0
    seen = set()

    for item in sorted(shared, key=lambda x: x["node_id"]):
        node_id = item["node_id"]
        if node_id in seen:
            continue
        seen.add(node_id)

        weight = WEIGHTS.get(item["node_type"])
        if weight is not None:
            remaining *= 1.0 - weight

    return round(1.0 - remaining, 4)


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cluster_runs (
            run_id TEXT PRIMARY KEY,
            algorithm TEXT NOT NULL,
            parameters_json TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at_utc TEXT NOT NULL,
            completed_at_utc TEXT
        );

        CREATE TABLE IF NOT EXISTS clusters (
            cluster_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES cluster_runs(run_id),
            label TEXT NOT NULL,
            confidence REAL CHECK(
                confidence IS NULL OR
                (confidence >= 0 AND confidence <= 1)
            ),
            summary TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cluster_memberships (
            cluster_id TEXT NOT NULL REFERENCES clusters(cluster_id),
            node_id TEXT NOT NULL REFERENCES infrastructure_nodes(node_id),
            membership_type TEXT NOT NULL DEFAULT 'candidate',
            PRIMARY KEY(cluster_id, node_id)
        );

        CREATE TABLE IF NOT EXISTS cluster_pair_scores (
            run_id TEXT NOT NULL REFERENCES cluster_runs(run_id),
            seed_a TEXT NOT NULL
                CHECK(seed_a IN ('S001','S002','S003','S004')),
            seed_b TEXT NOT NULL
                CHECK(seed_b IN ('S001','S002','S003','S004')),
            score REAL NOT NULL CHECK(score >= 0 AND score <= 1),
            status TEXT NOT NULL,
            shared_observables_json TEXT NOT NULL,
            PRIMARY KEY(run_id, seed_a, seed_b),
            CHECK(seed_a < seed_b)
        );
    """)
    conn.commit()


def collect_shared_observables(conn, anchors):
    from extract_entities import ensure_lifecycle_schema
    ensure_lifecycle_schema(conn)
    support = {}

    rows = conn.execute("""
        SELECT sa.seed_id, e.target_node_id, n.node_type,
               n.normalized_value, e.evidence_id, r.source_name,
               n.attributes_json
        FROM infrastructure_edges e
        JOIN seed_anchors sa
            ON sa.node_id = e.source_node_id
        JOIN infrastructure_nodes n
            ON n.node_id = e.target_node_id
        JOIN evidence_records r
            ON r.evidence_id = e.evidence_id
        WHERE e.relationship_type = 'co-observed-in-evidence'
          AND e.status = 'candidate'
          AND COALESCE(e.lifecycle_status,'active') = 'active'
          AND COALESCE(n.lifecycle_status,'active') = 'active'
          AND sa.seed_id IN ('S001','S002','S003','S004')
        ORDER BY sa.seed_id, e.target_node_id
    """).fetchall()

    for seed, node_id, node_type, value, evidence_id, source, attributes_json in rows:
        if node_type not in WEIGHTS:
            continue
        try:
            node_attributes = json.loads(attributes_json or "{}")
        except (TypeError, json.JSONDecodeError):
            node_attributes = {}
        if node_attributes.get("is_shared_infrastructure"):
            continue

        entity = support.setdefault(node_id, {
            "node_id": node_id,
            "node_type": node_type,
            "value": value,
            "seeds": {},
        })
        seed_support = entity["seeds"].setdefault(seed, {
            "evidence_ids": set(),
            "sources": set(),
        })
        seed_support["evidence_ids"].add(evidence_id)
        seed_support["sources"].add(source)

    pairs = []
    for seed_a, seed_b in combinations(sorted(anchors), 2):
        shared = []

        for entity in support.values():
            if seed_a not in entity["seeds"] or seed_b not in entity["seeds"]:
                continue

            shared.append({
                "node_id": entity["node_id"],
                "node_type": entity["node_type"],
                "value": entity["value"],
                "weight": WEIGHTS[entity["node_type"]],
                "support": {
                    seed_a: {
                        "evidence_ids": sorted(
                            entity["seeds"][seed_a]["evidence_ids"]
                        ),
                        "sources": sorted(
                            entity["seeds"][seed_a]["sources"]
                        ),
                    },
                    seed_b: {
                        "evidence_ids": sorted(
                            entity["seeds"][seed_b]["evidence_ids"]
                        ),
                        "sources": sorted(
                            entity["seeds"][seed_b]["sources"]
                        ),
                    },
                },
            })

        shared.sort(key=lambda item: (item["node_type"], item["value"]))
        score = score_shared_observables(shared)
        status = "candidate" if score >= THRESHOLD else "below_threshold"

        pairs.append({
            "seed_a": seed_a,
            "seed_b": seed_b,
            "score": score,
            "status": status,
            "shared": shared,
        })

    return pairs


def build_clusters(db_path: Path):
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    with sqlite3.connect(str(db_path), timeout=30) as conn:
        initialize_schema(conn)

        anchors = dict(conn.execute("""
            SELECT seed_id, node_id
            FROM seed_anchors
            WHERE seed_id IN ('S001','S002','S003','S004')
        """).fetchall())

        missing = set(SEEDS) - set(anchors)
        if missing:
            raise ValueError(f"Missing seed anchors: {sorted(missing)}")

        pairs = collect_shared_observables(conn, anchors)

        parameters = {
            "algorithm": ALGORITHM,
            "threshold": THRESHOLD,
            "weights": WEIGHTS,
            "score_formula": "1 - product(1 - unique observable weight)",
            "excluded_types": ["ipv4-addr", "ipv6-addr", "network-endpoint"],
        }

        signature_data = {
            "parameters": parameters,
            "pairs": [
                {
                    "seed_a": p["seed_a"],
                    "seed_b": p["seed_b"],
                    "score": p["score"],
                    "shared": p["shared"],
                    "status": p["status"],
                }
                for p in pairs
            ],
        }
        signature = json.dumps(
            signature_data, sort_keys=True, separators=(",", ":")
        )
        run_id = "cluster-run--" + hashlib.sha256(
            signature.encode("utf-8")
        ).hexdigest()

        candidate_count = sum(p["status"] == "candidate" for p in pairs)
        new_clusters = 0

        with conn:
            conn.execute("""
                INSERT OR IGNORE INTO cluster_runs
                (run_id, algorithm, parameters_json, status,
                 started_at_utc, completed_at_utc)
                VALUES (?, ?, ?, 'completed', ?, ?)
            """, (
                run_id,
                ALGORITHM,
                json.dumps(parameters, sort_keys=True),
                utc_now(),
                utc_now(),
            ))

            for pair in pairs:
                conn.execute("""
                    INSERT OR IGNORE INTO cluster_pair_scores
                    (run_id, seed_a, seed_b, score, status,
                     shared_observables_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    run_id,
                    pair["seed_a"],
                    pair["seed_b"],
                    pair["score"],
                    pair["status"],
                    json.dumps(pair["shared"], sort_keys=True),
                ))

                if pair["status"] != "candidate":
                    continue

                cluster_id = "cluster--" + hashlib.sha256(
                    f"{run_id}|{pair['seed_a']}|{pair['seed_b']}".encode()
                ).hexdigest()

                summary = (
                    f"Pairwise candidate based on "
                    f"{len(pair['shared'])} shared observable(s). "
                    f"Heuristic score={pair['score']}. "
                    "This score is not a probability and does not "
                    "establish common actor attribution. "
                    "CDN, shared hosting, and infrastructure reuse "
                    "may explain overlaps."
                )

                cur = conn.execute("""
                    INSERT OR IGNORE INTO clusters
                    (cluster_id, run_id, label, confidence, summary)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    cluster_id,
                    run_id,
                    f"{pair['seed_a']} + {pair['seed_b']} (candidate)",
                    pair["score"],
                    summary,
                ))
                new_clusters += cur.rowcount

                for seed in (pair["seed_a"], pair["seed_b"]):
                    conn.execute("""
                        INSERT OR IGNORE INTO cluster_memberships
                        (cluster_id, node_id, membership_type)
                        VALUES (?, ?, 'candidate-member')
                    """, (cluster_id, anchors[seed]))

        return run_id, pairs, new_clusters


def write_report(pairs, output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(".tmp")

    with temp.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "seed_a", "seed_b", "heuristic_score",
                "status", "shared_observable_count",
                "shared_observables",
            ],
        )
        writer.writeheader()
        for pair in pairs:
            writer.writerow({
                "seed_a": pair["seed_a"],
                "seed_b": pair["seed_b"],
                "heuristic_score": pair["score"],
                "status": pair["status"],
                "shared_observable_count": len(pair["shared"]),
                "shared_observables": json.dumps(
                    [
                        {
                            "type": item["node_type"],
                            "value": item["value"],
                            "weight": item["weight"],
                        }
                        for item in pair["shared"]
                    ],
                    ensure_ascii=False,
                ),
            })

    temp.replace(output)


def main() -> int:
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        run_id, pairs, new_clusters = build_clusters(DB_FILE)
        write_report(pairs, REPORT_FILE)

        print(f"Database: {DB_FILE}")
        print(f"Clustering run: {run_id}")
        print(f"Seed pairs scored: {len(pairs)}")
        print(f"Candidate pairs: {sum(p['status'] == 'candidate' for p in pairs)}")
        print(f"New candidate clusters: {new_clusters}")
        for pair in pairs:
            print(
                f"{pair['seed_a']} + {pair['seed_b']}: "
                f"score={pair['score']:.4f}, "
                f"status={pair['status']}, "
                f"shared={len(pair['shared'])}"
            )
        print(f"CSV report: {REPORT_FILE}")
        print("Scores are heuristic, not probabilities.")
        print("No actor attribution is inferred.")
        return 0
    except Exception as exc:
        logging.exception("Clustering failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
