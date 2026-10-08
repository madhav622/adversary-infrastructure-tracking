from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"
REPORT = ROOT / "reports" / "final_analyst_report.md"
EXPORT = ROOT / "exports" / "final_analyst_report.json"
LOG = ROOT / "logs" / "final_analyst_report.log"
SEEDS = ("S001", "S002", "S003", "S004")


def now_utc():
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def parse_json(value, field, expected_type):
    try:
        result = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON in {field}") from exc

    if not isinstance(result, expected_type):
        raise ValueError(f"Unexpected JSON type in {field}")
    return result


def md(value):
    return str(value if value is not None else "—").replace(
        "|", "\\|"
    ).replace("\r", " ").replace("\n", " ")


def build_report_data(db_path=DB):
    db_path = Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    uri = db_path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=30) as conn:
        conn.row_factory = sqlite3.Row

        available = {
            row["name"] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {
            "stix_objects", "infrastructure_nodes", "seed_anchors",
            "evidence_records", "entity_observations",
            "infrastructure_edges", "cluster_runs", "clusters",
            "cluster_memberships", "cluster_pair_scores", "alert_records",
        }
        missing = required - available
        if missing:
            raise ValueError(f"Missing database tables: {sorted(missing)}")

        table_names = sorted(required)
        totals = {
            table: conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in table_names
        }

        seeds = [
            dict(row) for row in conn.execute("""
                SELECT a.seed_id, n.value AS endpoint,
                       a.first_seen_utc, a.last_seen_utc,
                       a.observed_at_utc, a.source,
                       a.source_reference,
                       (SELECT COUNT(*) FROM evidence_records e
                        WHERE e.seed_id=a.seed_id) AS evidence_count,
                       (SELECT COUNT(*) FROM entity_observations o
                        JOIN evidence_records e
                          ON e.evidence_id=o.evidence_id
                        WHERE e.seed_id=a.seed_id) AS observation_count
                FROM seed_anchors a
                JOIN infrastructure_nodes n ON n.node_id=a.node_id
                WHERE a.seed_id IN ('S001','S002','S003','S004')
                ORDER BY a.seed_id
            """)
        ]
        if {row["seed_id"] for row in seeds} != set(SEEDS):
            raise ValueError("Database does not contain all four seed anchors")

        node_types = [
            dict(row) for row in conn.execute("""
                SELECT node_type, COUNT(*) AS count
                FROM infrastructure_nodes
                GROUP BY node_type ORDER BY node_type
            """)
        ]
        edge_statuses = [
            dict(row) for row in conn.execute("""
                SELECT status, COUNT(*) AS count
                FROM infrastructure_edges
                GROUP BY status ORDER BY status
            """)
        ]

        latest_row = conn.execute("""
            SELECT run_id, algorithm, status, parameters_json,
                   started_at_utc, completed_at_utc
            FROM cluster_runs
            ORDER BY started_at_utc DESC, run_id DESC
            LIMIT 1
        """).fetchone()

        latest_run = None
        pair_scores = []
        if latest_row:
            latest_run = dict(latest_row)
            latest_run["parameters"] = parse_json(
                latest_run.pop("parameters_json"),
                "cluster_runs.parameters_json", dict
            )
            latest_run["candidate_cluster_count"] = conn.execute(
                "SELECT COUNT(*) FROM clusters WHERE run_id=?",
                (latest_run["run_id"],),
            ).fetchone()[0]

            for row in conn.execute("""
                SELECT seed_a, seed_b, score, status,
                       shared_observables_json
                FROM cluster_pair_scores
                WHERE run_id=?
                ORDER BY seed_a, seed_b
            """, (latest_run["run_id"],)):
                pair_scores.append({
                    "seed_a": row["seed_a"],
                    "seed_b": row["seed_b"],
                    "score": row["score"],
                    "status": row["status"],
                    "shared_observables": parse_json(
                        row["shared_observables_json"],
                        "cluster_pair_scores.shared_observables_json",
                        list,
                    ),
                })

        alerts = []
        for row in conn.execute("""
            SELECT a.alert_id, a.alert_type, a.seed_id, a.node_id,
                   n.node_type, n.value AS observable, a.cluster_id,
                   a.severity, a.status, a.eligibility,
                   a.eligibility_reason, a.first_observed_utc,
                   a.last_observed_utc, a.created_at_utc,
                   a.lead_time_days, a.evidence_ids_json, a.sources_json,
                   a.summary, a.rationale, a.triaged_at_utc,
                   a.triaged_by, a.resolution_note, a.updated_at_utc
            FROM alert_records a
            JOIN infrastructure_nodes n ON n.node_id=a.node_id
            WHERE a.seed_id IN ('S001','S002','S003','S004')
            ORDER BY a.seed_id, a.alert_id
        """):
            if row["seed_id"] not in SEEDS:
                raise ValueError("Out-of-scope alert in report query")

            record = dict(row)
            record["evidence_ids"] = parse_json(
                record.pop("evidence_ids_json"),
                "alert_records.evidence_ids_json", list
            )
            record["sources"] = parse_json(
                record.pop("sources_json"),
                "alert_records.sources_json", list
            )
            alerts.append(record)

        history = []
        if "alert_triage_history" in available:
            history = [
                dict(row) for row in conn.execute("""
                    SELECT h.alert_id, a.seed_id,
                           h.previous_status, h.new_status,
                           h.previous_severity, h.new_severity,
                           h.reviewer, h.reason, h.changed_at_utc
                    FROM alert_triage_history h
                    JOIN alert_records a ON a.alert_id=h.alert_id
                    WHERE a.seed_id IN ('S001','S002','S003','S004')
                    ORDER BY h.changed_at_utc, h.history_id
                """)
            ]

        cluster_summaries = []
        for row in conn.execute("""
            SELECT cluster_id, run_id, label, confidence, summary
            FROM clusters
            ORDER BY cluster_id
        """):
            cluster_summaries.append(dict(row))

    def count_by(rows, key):
        result = {}
        for row in rows:
            label = row.get(key) or "unknown"
            result[label] = result.get(label, 0) + 1
        return dict(sorted(result.items()))

    return {
        "generated_at_utc": now_utc(),
        "scope": list(SEEDS),
        "database": "database/intel.db",
        "totals": totals,
        "node_types": node_types,
        "edge_statuses": edge_statuses,
        "seeds": seeds,
        "latest_cluster_run": latest_run,
        "pair_scores": pair_scores,
        "clusters": cluster_summaries,
        "alert_summary": {
            "total": len(alerts),
            "by_status": count_by(alerts, "status"),
            "by_severity": count_by(alerts, "severity"),
            "by_eligibility": count_by(alerts, "eligibility"),
        },
        "alerts": alerts,
        "triage_history": history,
        "limitations": [
            "Alert presence indicates imported passive evidence, not globally new infrastructure.",
            "Heuristic cluster scores are not probabilities.",
            "No common-actor attribution is inferred.",
            "Lead time is unknown without a verified outcome timestamp.",
            "Blocked is a manual triage status, not an automated blocking action.",
            "Source reliability grades are not configured.",
        ],
    }


def render_markdown(data):
    totals = data["totals"]
    summary = data["alert_summary"]
    lines = [
        "# Adversary Infrastructure Tracking and Clustering",
        "",
        "## Final Analyst Report",
        "",
        f"Generated (UTC): {md(data['generated_at_utc'])}",
        "",
        "Scope: " + ", ".join(data["scope"]),
        "",
        "## 1. Executive summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]

    for label, key in (
        ("STIX objects", "stix_objects"),
        ("Infrastructure nodes", "infrastructure_nodes"),
        ("Seed anchors", "seed_anchors"),
        ("Evidence records", "evidence_records"),
        ("Entity observations", "entity_observations"),
        ("Infrastructure edges", "infrastructure_edges"),
        ("Alert records", "alert_records"),
        ("Candidate clusters", "clusters"),
    ):
        lines.append(f"| {label} | {totals[key]} |")

    lines.extend(["", "## 2. Seed inventory", ""])
    lines.extend([
        "| Seed | Endpoint | Source | First seen (UTC) | Evidence | Observations |",
        "|---|---|---|---|---:|---:|",
    ])
    for seed in data["seeds"]:
        lines.append(
            f"| {md(seed['seed_id'])} | {md(seed['endpoint'])} "
            f"| {md(seed['source'])} | {md(seed['first_seen_utc'])} "
            f"| {seed['evidence_count']} | {seed['observation_count']} |"
        )

    lines.extend(["", "## 3. Infrastructure node types", ""])
    lines.extend(["| Node type | Count |", "|---|---:|"])
    for row in data["node_types"]:
        lines.append(f"| {md(row['node_type'])} | {row['count']} |")

    lines.extend(["", "## 4. Relationship status", ""])
    lines.extend(["| Status | Count |", "|---|---:|"])
    for row in data["edge_statuses"]:
        lines.append(f"| {md(row['status'])} | {row['count']} |")

    lines.extend(["", "## 5. Clustering", ""])
    run = data["latest_cluster_run"]
    if run:
        lines.extend([
            f"- Algorithm: `{md(run['algorithm'])}`",
            f"- Run ID: `{md(run['run_id'])}`",
            f"- Status: {md(run['status'])}",
            f"- Candidate clusters: {run['candidate_cluster_count']}",
            "",
            "| Pair | Score | Result | Shared observables |",
            "|---|---:|---|---:|",
        ])
        for pair in data["pair_scores"]:
            lines.append(
                f"| {pair['seed_a']} + {pair['seed_b']} "
                f"| {pair['score']:.4f} | {md(pair['status'])} "
                f"| {len(pair['shared_observables'])} |"
            )
    else:
        lines.append("No clustering run recorded.")

    lines.extend(["", "## 6. Alert summary", ""])
    lines.extend(["| Dimension | Value |", "|---|---:|"])
    lines.append(f"| Total alerts | {summary['total']} |")
    for status, number in summary["by_status"].items():
        lines.append(f"| Status: {md(status)} | {number} |")
    for severity, number in summary["by_severity"].items():
        lines.append(f"| Severity: {md(severity)} | {number} |")
    for eligibility, number in summary["by_eligibility"].items():
        lines.append(f"| Eligibility: {md(eligibility)} | {number} |")

    lines.extend(["", "## 7. Alert register", ""])
    lines.extend([
        "| Seed | Observable | Type | Severity | Status | Eligibility | First observed | Evidence count |",
        "|---|---|---|---|---|---|---|---:|",
    ])
    for alert in data["alerts"]:
        lines.append(
            f"| {md(alert['seed_id'])} | {md(alert['observable'])} "
            f"| {md(alert['node_type'])} | {md(alert['severity'])} "
            f"| {md(alert['status'])} | {md(alert['eligibility'])} "
            f"| {md(alert['first_observed_utc'])} "
            f"| {len(alert['evidence_ids'])} |"
        )

    lines.extend(["", "## 8. Analyst triage history", ""])
    if data["triage_history"]:
        lines.extend([
            "| Seed | Alert ID | Previous | New status | Reviewer | Changed (UTC) | Reason |",
            "|---|---|---|---|---|---|---|",
        ])
        for h in data["triage_history"]:
            lines.append(
                f"| {md(h['seed_id'])} | {md(h['alert_id'])} "
                f"| {md(h['previous_status'])} | {md(h['new_status'])} "
                f"| {md(h['reviewer'])} | {md(h['changed_at_utc'])} "
                f"| {md(h['reason'])} |"
            )
    else:
        lines.append("No analyst triage history is recorded.")

    lines.extend(["", "## 9. Limitations", ""])
    lines.extend(f"- {md(item)}" for item in data["limitations"])
    return "\n".join(lines) + "\n"


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(content, encoding="utf-8")
    temp.replace(path)


def main():
    logging.basicConfig(
        filename=str(LOG),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        data = build_report_data()
        atomic_write(
            REPORT,
            render_markdown(data),
        )
        atomic_write(
            EXPORT,
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        )
        logging.info("Final analyst report generated")
        print(f"Markdown report: {REPORT}")
        print(f"JSON report: {EXPORT}")
        print(f"Seeds: {len(data['seeds'])}")
        print(f"Alerts: {data['alert_summary']['total']}")
        print(f"Triage history entries: {len(data['triage_history'])}")
        print(f"Candidate clusters: {len(data['clusters'])}")
        return 0
    except Exception as exc:
        logging.exception("Final analyst report generation failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
