from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.data_access import read_query

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"

st.set_page_config(
    page_title="Adversary Infrastructure Tracking",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛰️ Adversary Infrastructure Tracking & Clustering")
st.caption("Local CTI analyst workbench | Passive evidence | S001–S004")


@st.cache_data(ttl=10, show_spinner=False)
def q(sql: str, params: tuple = ()) -> pd.DataFrame:
    return read_query(sql, params)


def show_df(data: pd.DataFrame, message: str = "No records found.") -> None:
    if data.empty:
        st.info(message)
    else:
        st.dataframe(data, hide_index=True, width="stretch")


def count(table: str) -> int:
    allowed = {
        "stix_objects", "infrastructure_nodes", "seed_anchors",
        "evidence_records", "entity_observations",
        "infrastructure_edges", "clusters",
    }
    if table not in allowed:
        raise ValueError("Unsupported count table")
    result = q(f"SELECT COUNT(*) AS total FROM {table}")
    return int(result.iloc[0]["total"])


if not DB.is_file():
    st.error(f"Database not found: {DB}")
    st.stop()

try:
    totals = {
        "STIX objects": count("stix_objects"),
        "Infrastructure nodes": count("infrastructure_nodes"),
        "Evidence records": count("evidence_records"),
        "Entity observations": count("entity_observations"),
        "Candidate edges": int(q(
            "SELECT COUNT(*) AS n FROM infrastructure_edges "
            "WHERE status='candidate'"
        ).iloc[0]["n"]),
        "Candidate clusters": count("clusters"),
    }

    seeds = q("""
        SELECT a.seed_id, n.value AS endpoint,
               a.first_seen_utc, a.last_seen_utc,
               a.observed_at_utc, a.source, a.source_reference,
               (SELECT COUNT(*) FROM evidence_records e
                WHERE e.seed_id=a.seed_id) AS evidence_files,
               (SELECT COUNT(*) FROM entity_observations o
                JOIN evidence_records e
                ON e.evidence_id=o.evidence_id
                WHERE e.seed_id=a.seed_id) AS observations
        FROM seed_anchors a
        JOIN infrastructure_nodes n ON n.node_id=a.node_id
        WHERE a.seed_id IN ('S001','S002','S003','S004')
        ORDER BY a.seed_id
    """)

    if seeds.empty:
        st.error("Seed anchors are not available in the database.")
        st.stop()

    selected_seed = st.sidebar.selectbox(
        "Filter by seed",
        options=["All"] + seeds["seed_id"].tolist(),
    )

    if st.sidebar.button("Refresh database data"):
        st.cache_data.clear()
        st.rerun()

    st.sidebar.divider()
    st.sidebar.caption("Database: database/intel.db")
    st.sidebar.caption("Scope: S001–S004")
    st.sidebar.caption("Read-only dashboard")

    st.info(
        "This dashboard uses locally collected evidence. "
        "It does not scan live targets, automatically block IOCs "
        "or attribute infrastructure to a threat actor."
    )

    tabs = st.tabs([
        "Overview",
        "Seeds",
        "Observables",
        "Relationships",
        "Clustering",
        "Evidence",
        "Exports",
    ])

    with tabs[0]:
        cols = st.columns(3)
        metrics = list(totals.items())
        for i, (label, value) in enumerate(metrics):
            with cols[i % 3]:
                st.metric(label, value)

        st.subheader("Infrastructure node types")
        node_types = q("""
            SELECT node_type, COUNT(*) AS count
            FROM infrastructure_nodes
            GROUP BY node_type
            ORDER BY count DESC, node_type
        """)
        if not node_types.empty:
            st.bar_chart(
                node_types.set_index("node_type")["count"]
            )

        st.subheader("Relationship status")
        edge_types = q("""
            SELECT status, COUNT(*) AS count
            FROM infrastructure_edges
            GROUP BY status ORDER BY status
        """)
        if not edge_types.empty:
            st.bar_chart(edge_types.set_index("status")["count"])

        st.subheader("Latest clustering run")
        latest = q("""
            SELECT run_id, algorithm, status, started_at_utc,
                   completed_at_utc
            FROM cluster_runs
            ORDER BY started_at_utc DESC, run_id DESC
            LIMIT 1
        """)
        show_df(latest)

    with tabs[1]:
        st.subheader("Seed inventory")
        seed_view = seeds.copy()
        if selected_seed != "All":
            seed_view = seed_view[
                seed_view["seed_id"] == selected_seed
            ]
        show_df(seed_view)

    with tabs[2]:
        st.subheader("Extracted infrastructure observables")
        nodes = q("""
            SELECT node_id, node_type, value, normalized_value,
                   created_at_utc
            FROM infrastructure_nodes
            ORDER BY node_type, value
        """)
        node_types = ["All"] + (
            sorted(nodes["node_type"].dropna().unique().tolist())
            if not nodes.empty else []
        )
        selected_type = st.selectbox("Observable type", node_types)
        search = st.text_input("Search observables", placeholder="IP, domain, hash...")

        if selected_type != "All":
            nodes = nodes[nodes["node_type"] == selected_type]
        if search.strip():
            mask = nodes.astype(str).apply(
                lambda col: col.str.contains(
                    search.strip(), case=False, regex=False
                )
            ).any(axis=1)
            nodes = nodes[mask]

        show_df(nodes)

    with tabs[3]:
        st.subheader("Evidence-backed relationships")
        edges = q("""
            SELECT e.edge_id, sa.seed_id,
                   src.value AS source,
                   tgt.node_type AS target_type,
                   tgt.value AS target,
                   e.relationship_type, e.status, e.confidence,
                   e.evidence_id, e.first_seen_utc, e.last_seen_utc
            FROM infrastructure_edges e
            LEFT JOIN infrastructure_nodes src
                ON src.node_id=e.source_node_id
            LEFT JOIN infrastructure_nodes tgt
                ON tgt.node_id=e.target_node_id
            LEFT JOIN seed_anchors sa
                ON sa.node_id=e.source_node_id
            ORDER BY sa.seed_id, e.edge_id
        """)
        statuses = ["All"] + (
            sorted(edges["status"].dropna().unique().tolist())
            if not edges.empty else []
        )
        selected_status = st.selectbox("Relationship status", statuses)
        if selected_seed != "All" and not edges.empty:
            edges = edges[edges["seed_id"] == selected_seed]
        if selected_status != "All":
            edges = edges[edges["status"] == selected_status]

        show_df(edges)

        if not edges.empty:
            edge_ids = edges["edge_id"].tolist()
            edge_id = st.selectbox("Inspect relationship rationale", edge_ids)
            rationale = q(
                "SELECT rationale FROM infrastructure_edges WHERE edge_id=?",
                (edge_id,),
            )
            if not rationale.empty:
                st.write(rationale.iloc[0]["rationale"])

    with tabs[4]:
        st.subheader("Infrastructure clustering")
        latest = q("""
            SELECT run_id, algorithm, status, parameters_json,
                   started_at_utc, completed_at_utc
            FROM cluster_runs
            ORDER BY started_at_utc DESC, run_id DESC
            LIMIT 1
        """)

        if latest.empty:
            st.info("No clustering run is recorded.")
        else:
            run = latest.iloc[0]
            st.write(f"Algorithm: `{run['algorithm']}`")
            st.write(f"Run ID: `{run['run_id']}`")
            params = json.loads(run["parameters_json"])
            st.write(f"Configured threshold: {params.get('threshold', '—')}")

            pair_scores = q("""
                SELECT seed_a, seed_b, score, status,
                       shared_observables_json
                FROM cluster_pair_scores
                WHERE run_id=?
                ORDER BY seed_a, seed_b
            """, (run["run_id"],))

            if not pair_scores.empty:
                visible = pair_scores[
                    ["seed_a", "seed_b", "score", "status"]
                ].copy()
                show_df(visible)
                st.caption(
                    "Scores are heuristic values, not probabilities. "
                    "Below-threshold pairs are not evidence of unrelatedness."
                )

                selected_pair = st.selectbox(
                    "Inspect shared observables",
                    options=pair_scores.apply(
                        lambda r: f"{r['seed_a']} + {r['seed_b']}", axis=1
                    ).tolist(),
                )
                selected_row = pair_scores[
                    pair_scores.apply(
                        lambda r: f"{r['seed_a']} + {r['seed_b']}"
                        == selected_pair, axis=1
                    )
                ].iloc[0]
                st.json(json.loads(selected_row["shared_observables_json"]))

            else:
                st.info("No pair scores are stored for the latest run.")

            clusters = q("""
                SELECT cluster_id, label, confidence, summary
                FROM clusters WHERE run_id=?
                ORDER BY cluster_id
            """, (run["run_id"],))
            st.subheader("Candidate clusters")
            show_df(clusters, "No candidate clusters met the configured threshold.")

    with tabs[5]:
        st.subheader("Collected evidence")
        evidence = q("""
            SELECT evidence_id, seed_id, source_name, evidence_type,
                   source_reference, raw_file_path, raw_sha256,
                   observed_at_utc
            FROM evidence_records
            WHERE seed_id IN ('S001','S002','S003','S004')
            ORDER BY seed_id, source_name, evidence_id
        """)
        if selected_seed != "All":
            evidence = evidence[evidence["seed_id"] == selected_seed]

        show_df(evidence)

        if not evidence.empty:
            evidence_id = st.selectbox(
                "View evidence details",
                options=evidence["evidence_id"].tolist(),
            )
            details = q(
                "SELECT details_json FROM evidence_records WHERE evidence_id=?",
                (evidence_id,),
            )
            if not details.empty:
                with st.expander("Raw evidence details", expanded=False):
                    st.json(json.loads(details.iloc[0]["details_json"]))

    with tabs[6]:
        st.subheader("Download project outputs")
        exports = [
            ("STIX 2.1 bundle", ROOT / "exports/seeds_s001_s004_stix21.json", "application/json"),
            ("Analysis summary (JSON)", ROOT / "exports/infrastructure_analysis_summary.json", "application/json"),
            ("SIEM IOC feed (JSON)", ROOT / "exports/siem_ioc_feed.json", "application/json"),
            ("SIEM IOC feed (CSV)", ROOT / "exports/siem_ioc_feed.csv", "text/csv"),
            ("Cluster scores (CSV)", ROOT / "exports/cluster_pair_scores.csv", "text/csv"),
            ("Analysis report (Markdown)", ROOT / "reports/infrastructure_analysis_report.md", "text/markdown"),
        ]

        for index, (label, path, mime) in enumerate(exports):
            if path.is_file():
                st.download_button(
                    label=f"Download {label}",
                    data=path.read_bytes(),
                    file_name=path.name,
                    mime=mime,
                    key=f"download_{index}",
                )
            else:
                st.caption(f"Not available yet: {label}")

except Exception as exc:
    st.error(f"Dashboard data error: {exc}")
