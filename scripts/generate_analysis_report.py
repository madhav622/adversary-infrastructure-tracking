from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"
REPORT = ROOT / "reports" / "infrastructure_analysis_report.md"
EXPORT = ROOT / "exports" / "infrastructure_analysis_summary.json"
LOG = ROOT / "logs" / "report_generator.log"
SEEDS = ("S001", "S002", "S003", "S004")

TABLES = (
    "stix_objects", "infrastructure_nodes", "seed_anchors",
    "evidence_records", "entity_observations", "infrastructure_edges",
    "cluster_runs", "clusters", "cluster_memberships",
    "cluster_pair_scores",
)


def now_utc():
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def collect_summary(db_path: Path) -> dict:
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    with sqlite3.connect(str(db_path), timeout=30) as conn:
        conn.row_factory = sqlite3.Row
        existing = {
            row["name"] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = set(TABLES) - existing
        if missing:
            raise ValueError(f"Required tables missing: {sorted(missing)}")

        totals = {}
        for table in TABLES:
            totals[table] = conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

        seed_rows = conn.execute("""
            SELECT sa.seed_id, n.value AS endpoint,
                   sa.first_seen_utc, sa.last_seen_utc,
                   sa.observed_at_utc, sa.source, sa.source_reference,
                   (SELECT COUNT(*) FROM evidence_records er
                    WHERE er.seed_id = sa.seed_id) AS evidence_files,
                   (SELECT COUNT(*) FROM entity_observations eo
                    JOIN evidence_records er
                    ON er.evidence_id = eo.evidence_id
                    WHERE er.seed_id = sa.seed_id) AS observations
            FROM seed_anchors sa
            JOIN infrastructure_nodes n ON n.node_id = sa.node_id
            WHERE sa.seed_id IN ('S001','S002','S003','S004')
            ORDER BY sa.seed_id
        """).fetchall()

        if {row["seed_id"] for row in seed_rows} != set(SEEDS):
            raise ValueError("Expected all four seed anchors in database")

        node_types = [
            dict(row) for row in conn.execute("""
                SELECT node_type, COUNT(*) AS count
                FROM infrastructure_nodes
                GROUP BY node_type
                ORDER BY node_type
            """)
        ]

        edge_statuses = [
            dict(row) for row in conn.execute("""
                SELECT status, COUNT(*) AS count
                FROM infrastructure_edges
                GROUP BY status
                ORDER BY status
            """)
        ]

        latest = conn.execute("""
            SELECT run_id, algorithm, parameters_json, started_at_utc,
                   completed_at_utc, status
            FROM cluster_runs
            ORDER BY started_at_utc DESC, run_id DESC
            LIMIT 1
        """).fetchone()

        run = None
        pairs = []
        if latest:
            run = dict(latest)
            run["parameters"] = json.loads(run.pop("parameters_json"))

            pair_rows = conn.execute("""
                SELECT seed_a, seed_b, score, status,
                       shared_observables_json
                FROM cluster_pair_scores
                WHERE run_id = ?
                ORDER BY seed_a, seed_b
            """, (run["run_id"],)).fetchall()

            for row in pair_rows:
                shared = json.loads(row["shared_observables_json"])
                pairs.append({
                    "seed_a": row["seed_a"],
                    "seed_b": row["seed_b"],
                    "score": row["score"],
                    "status": row["status"],
                    "shared_count": len(shared),
                    "shared": shared,
                })

            run["candidate_clusters"] = conn.execute(
                "SELECT COUNT(*) FROM clusters WHERE run_id = ?",
                (run["run_id"],),
            ).fetchone()[0]

    return {
        "generated_at_utc": now_utc(),
        "scope": list(SEEDS),
        "totals": totals,
        "seeds": [dict(row) for row in seed_rows],
        "node_types": node_types,
        "edge_statuses": edge_statuses,
        "latest_run": run,
        "pair_scores": pairs,
    }


def safe(value) -> str:
    return str(value if value is not None else "—").replace(
        "|", "\\|"
    ).replace("\r", " ").replace("\n", " ")


def render_report(data: dict) -> str:
    totals = data["totals"]
    run = data["latest_run"]
    lines = [
        "# Adversary Infrastructure Tracking and Clustering",
        "",
        "## Analysis Report",
        "",
        f"Generated (UTC): {data['generated_at_utc']}",
        "",
        "### Scope",
        "",
        "Seed IDs: " + ", ".join(data["scope"]),
        "",
        "S005 is excluded from this analysis.",
        "",
        "### Project statistics",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]

    for title, key in (
        ("STIX objects", "stix_objects"),
        ("Infrastructure nodes", "infrastructure_nodes"),
        ("Seed anchors", "seed_anchors"),
        ("Evidence records", "evidence_records"),
        ("Entity observations", "entity_observations"),
        ("Infrastructure edges", "infrastructure_edges"),
        ("Cluster runs", "cluster_runs"),
        ("Clusters", "clusters"),
        ("Cluster memberships", "cluster_memberships"),
    ):
        lines.append(f"| {title} | {totals[key]} |")

    lines.extend([
        "",
        "### Seed overview",
        "",
        "| Seed | Endpoint | First seen (UTC) | Last seen (UTC) | Evidence files | Observations | Source |",
        "|---|---|---|---|---:|---:|---|",
    ])

    for seed in data["seeds"]:
        lines.append(
            f"| {safe(seed['seed_id'])} "
            f"| {safe(seed['endpoint'])} "
            f"| {safe(seed['first_seen_utc'])} "
            f"| {safe(seed['last_seen_utc'])} "
            f"| {seed['evidence_files']} "
            f"| {seed['observations']} "
            f"| {safe(seed['source'])} |"
        )

    lines.extend(["", "### Infrastructure node types", ""])
    if data["node_types"]:
        lines.extend(["| Type | Count |", "|---|---:|"])
        for item in data["node_types"]:
            lines.append(
                f"| {safe(item['node_type'])} | {item['count']} |"
            )
    else:
        lines.append("No infrastructure nodes recorded.")

    lines.extend(["", "### Relationship status", ""])
    if data["edge_statuses"]:
        lines.extend(["| Status | Count |", "|---|---:|"])
        for item in data["edge_statuses"]:
            lines.append(
                f"| {safe(item['status'])} | {item['count']} |"
            )
    else:
        lines.append("No relationships recorded.")

    lines.extend(["", "### Clustering results", ""])
    if run is None:
        lines.append("No clustering run is available.")
    else:
        lines.extend([
            f"- Algorithm: `{safe(run['algorithm'])}`",
            f"- Run ID: `{safe(run['run_id'])}`",
            f"- Status: {safe(run['status'])}",
            f"- Threshold: {safe(run['parameters'].get('threshold'))}",
            f"- Candidate clusters: {run['candidate_clusters']}",
            "",
            "| Seed pair | Score | Status | Shared observables |",
            "|---|---:|---|---:|",
        ])

        for pair in data["pair_scores"]:
            lines.append(
                f"| {pair['seed_a']} + {pair['seed_b']} "
                f"| {pair['score']:.4f} "
                f"| {safe(pair['status'])} "
                f"| {pair['shared_count']} |"
            )

        candidates = [
            pair for pair in data["pair_scores"]
            if pair["status"] == "candidate"
        ]
        if not candidates:
            lines.extend([
                "",
                "No pair met the configured candidate threshold "
                "under the current evidence and scoring rules.",
                "This does not establish that the seed infrastructures "
                "are unrelated.",
            ])

    lines.extend([
        "",
        "### Methodology and limitations",
        "",
        "- Scores are rule-based heuristic values, not probabilities.",
        "- Shared IP addresses are excluded from the current pair score.",
        "- A candidate relationship is not proof of direct connectivity "
        "or common control.",
        "- CDN usage, shared hosting, infrastructure reuse, and "
        "temporal changes may affect apparent overlap.",
        "- No threat-actor attribution is inferred.",
        "- The report reflects the currently imported evidence only.",
        "- Some source first-seen timestamps were blank; available "
        "listing dates from the seed notes were used as fallbacks.",
        "",
        "### Provenance",
        "",
        "Raw evidence records, their source names, paths, and SHA-256 "
        "hashes are retained in the local SQLite database.",
        "",
    ])
    return "\n".join(lines)


def atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    logging.basicConfig(
        filename=str(LOG),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        data = collect_summary(DB)
        report = render_report(data)

        atomic_write(REPORT, report)
        atomic_write(
            EXPORT,
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        )

        logging.info("Analysis report generated successfully")
        print(f"Markdown report: {REPORT}")
        print(f"JSON summary: {EXPORT}")
        print(f"Seeds: {len(data['seeds'])}")
        print(f"Evidence records: {data['totals']['evidence_records']}")
        print(f"Infrastructure nodes: {data['totals']['infrastructure_nodes']}")
        print(f"Candidate clusters: {data['latest_run']['candidate_clusters'] if data['latest_run'] else 0}")
        return 0
    except Exception as exc:
        logging.exception("Report generation failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
