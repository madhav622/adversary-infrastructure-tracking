from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.data_access import read_query
from dashboard.pivot import find_seed, find_pivots
from dashboard.source_quality import get_source_quality, get_source_coverage
from dashboard.false_link_review import load_false_link_candidates

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "intel.db"

st.set_page_config(page_title="AITC | Threat Intelligence Workbench",
                   page_icon="🛰️", layout="wide")

TYPE_COLOR = {"ipv4-addr": "#22d3ee", "domain-name": "#a78bfa",
              "file-hash-sha256": "#f472b6", "certificate-fingerprint": "#fbbf24",
              "network-endpoint": "#34d399"}
CSS = """
<style>
.block-container{padding-top:1.2rem;max-width:1500px}
.hero{background:linear-gradient(120deg,#0f1b3a 0%,#12324a 60%,#0e2a3a 100%);
 border:1px solid #1f3b5c;border-radius:14px;padding:20px 26px;margin-bottom:14px}
.hero h1{margin:0;font-size:1.7rem;color:#f1f5f9;letter-spacing:.3px}
.hero p{margin:4px 0 0;color:#8fa6c4;font-size:.85rem}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.72rem;
 font-weight:600;margin-right:6px;border:1px solid}
.p-green{color:#34d399;border-color:#1c6b53;background:#0f2b25}
.p-cyan{color:#22d3ee;border-color:#1b6273;background:#0d2a33}
.p-amber{color:#fbbf24;border-color:#7a5c12;background:#2e2410}
.kpi{background:#121a2f;border:1px solid #1f2b47;border-left:4px solid var(--c);
 border-radius:10px;padding:14px 16px}
.kpi .l{color:#8fa6c4;font-size:.75rem;text-transform:uppercase;letter-spacing:.8px}
.kpi .v{color:#f8fafc;font-size:1.9rem;font-weight:700;line-height:1.2}
.kpi .s{color:#64748b;font-size:.72rem}
.note{background:#121a2f;border:1px solid #1f2b47;border-radius:10px;
 padding:12px 16px;color:#b6c4da;font-size:.85rem}
h2,h3{color:#e2e8f0!important}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


@st.cache_data(ttl=10, show_spinner=False)
def q(sql: str, params: tuple = ()) -> pd.DataFrame:
    return read_query(sql, params)


def kpi(label: str, value, sub: str, color: str) -> None:
    st.markdown(
        f'<div class="kpi" style="--c:{color}"><div class="l">{label}</div>'
        f'<div class="v">{value}</div><div class="s">{sub}</div></div>',
        unsafe_allow_html=True)


def show_df(df: pd.DataFrame, msg: str = "No records found.") -> None:
    if df.empty:
        st.info(msg)
    else:
        st.dataframe(df, hide_index=True, width="stretch")


def style_fig(fig: go.Figure, height: int = 340) -> go.Figure:
    fig.update_layout(height=height, paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font_color="#cbd5e1",
                      margin=dict(l=10, r=10, t=30, b=10))
    return fig


def scalar(sql: str) -> int:
    return int(q(sql).iloc[0, 0])


if not DB.is_file():
    st.error(f"Database not found: {DB}")
    st.stop()

try:
    seeds = q("""
        SELECT a.seed_id, n.value AS endpoint, a.first_seen_utc,
               a.observed_at_utc, a.source, a.source_reference,
               (SELECT COUNT(*) FROM evidence_records e WHERE e.seed_id=a.seed_id) AS evidence_files,
               (SELECT COUNT(*) FROM entity_observations o
                  JOIN evidence_records e ON e.evidence_id=o.evidence_id
                 WHERE e.seed_id=a.seed_id) AS observations
        FROM seed_anchors a JOIN infrastructure_nodes n ON n.node_id=a.node_id
        WHERE a.seed_id IN ('S001','S002','S003','S004') ORDER BY a.seed_id""")
    if seeds.empty:
        st.error("Seed anchors are not available in the database.")
        st.stop()

    with st.sidebar:
        st.markdown("### 🛰️ AITC Workbench")
        selected_seed = st.selectbox("Seed filter", ["All"] + seeds["seed_id"].tolist())
        if st.button("↻ Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()
        st.divider()
        st.caption("Source: database/intel.db (read-only)")
        st.caption("Scope: S001–S004 | Passive evidence only")

    total_nodes = scalar("SELECT COUNT(*) FROM infrastructure_nodes")
    total_edges = scalar("SELECT COUNT(*) FROM infrastructure_edges")
    weak_edges = scalar("SELECT COUNT(*) FROM infrastructure_edges WHERE confidence<=0.2")
    n_clusters = scalar("SELECT COUNT(*) FROM clusters")

    st.markdown(
        '<div class="hero"><h1>🛰️ Adversary Infrastructure Tracking &amp; Clustering</h1>'
        '<p>CTI analyst workbench &middot; evidence-backed &middot; '
        'cluster and actor attribution kept separate</p>'
        '<div style="margin-top:10px"><span class="pill p-green">PASSIVE COLLECTION</span>'
        '<span class="pill p-cyan">READ-ONLY</span>'
        '<span class="pill p-amber">NO ACTOR ATTRIBUTION</span></div></div>',
        unsafe_allow_html=True)

    tabs = st.tabs(["Overview", "Infrastructure graph", "Seeds", "Observables",
                    "Relationships", "Clustering", "Evidence", "Exports",
                    "Pivot workbench", "Source quality", "False-link review"])

    with tabs[0]:
        c = st.columns(5)
        with c[0]: kpi("Seeds", len(seeds), "S001–S004", "#22d3ee")
        with c[1]: kpi("Infra nodes", total_nodes, "extracted observables", "#a78bfa")
        with c[2]: kpi("Evidence records", scalar("SELECT COUNT(*) FROM evidence_records"), "raw files hashed", "#34d399")
        with c[3]: kpi("Candidate edges", total_edges, f"{weak_edges} weak (conf ≤ 0.2)", "#fbbf24")
        with c[4]: kpi("Candidate clusters", n_clusters, "threshold-based", "#f472b6")
        st.write("")
        l, r = st.columns(2)
        types = q("SELECT node_type, COUNT(*) AS n FROM infrastructure_nodes GROUP BY node_type ORDER BY n DESC")
        with l:
            st.subheader("Observable mix")
            fig = go.Figure(go.Pie(labels=types["node_type"], values=types["n"], hole=.62,
                            marker=dict(colors=[TYPE_COLOR.get(t, "#64748b") for t in types["node_type"]])))
            st.plotly_chart(style_fig(fig), width="stretch")
        per_seed = q("""SELECT sa.seed_id, e.status, COUNT(*) AS n FROM infrastructure_edges e
                        JOIN seed_anchors sa ON sa.node_id=e.source_node_id
                        GROUP BY sa.seed_id, e.status ORDER BY sa.seed_id""")
        with r:
            st.subheader("Relationships per seed")
            fig = go.Figure()
            for status, grp in per_seed.groupby("status"):
                fig.add_bar(x=grp["seed_id"], y=grp["n"], name=status)
            fig.update_layout(barmode="stack")
            st.plotly_chart(style_fig(fig), width="stretch")
        st.subheader("Analyst notes")
        st.markdown(
            f'<div class="note"><b>{weak_edges} of {total_edges}</b> relationships are weak '
            'co-observation candidates (rule score 0.2, not a probability). '
            'Netblock boundary IPs and detection labels (e.g. malware names) can appear as '
            'nodes; treat them as weak pivots and review before any cluster merge.</div>',
            unsafe_allow_html=True)
        st.write("")
        st.subheader("Latest clustering run")
        show_df(q("""SELECT run_id, algorithm, status, started_at_utc, completed_at_utc
                     FROM cluster_runs ORDER BY started_at_utc DESC LIMIT 1"""))

    with tabs[1]:
        st.subheader("Seed-centred infrastructure graph")
        g_edges = q("""SELECT sa.seed_id, src.value AS s, src.node_type AS st,
                              tgt.value AS t, tgt.node_type AS tt, e.confidence, e.first_seen_utc, e.edge_id, e.relationship_type, e.evidence_id, e.status
                       FROM infrastructure_edges e
                       JOIN infrastructure_nodes src ON src.node_id=e.source_node_id
                       JOIN infrastructure_nodes tgt ON tgt.node_id=e.target_node_id
                       LEFT JOIN seed_anchors sa ON sa.node_id=e.source_node_id""")
        if selected_seed != "All":
            g_edges = g_edges[g_edges["seed_id"] == selected_seed]

        # Filter by the stored evidence observation timestamp.
        if not g_edges.empty:
            g_edges["evidence_time"] = pd.to_datetime(
                g_edges["first_seen_utc"], utc=True, errors="coerce"
            )
            time_values = g_edges["evidence_time"].dropna().dt.tz_convert(None)

            if not time_values.empty:
                earliest = time_values.min().to_pydatetime()
                latest = time_values.max().to_pydatetime()

                if earliest >= latest:
                    from datetime import timedelta
                    latest = earliest + timedelta(seconds=1)

                start_time, end_time = st.slider(
                    "Evidence observation window (UTC)",
                    min_value=earliest,
                    max_value=latest,
                    value=(earliest, latest),
                    format="YYYY-MM-DD HH:mm",
                )

                start_utc = pd.Timestamp(start_time).tz_localize("UTC")
                end_utc = pd.Timestamp(end_time).tz_localize("UTC")

                valid_time = (
                    g_edges["evidence_time"].isna()
                    | g_edges["evidence_time"].between(start_utc, end_utc)
                )
                g_edges = g_edges[valid_time]

        if g_edges.empty:
            st.info("No edges to draw for this filter.")
        else:
            G = nx.Graph()
            for row in g_edges.itertuples():
                G.add_node(row.s, kind=row.st)
                G.add_node(row.t, kind=row.tt)
                G.add_edge(row.s, row.t)
            pos = nx.spring_layout(G, seed=7, k=0.7)
            ex, ey = [], []
            for a, b in G.edges():
                ex += [pos[a][0], pos[b][0], None]
                ey += [pos[a][1], pos[b][1], None]
            fig = go.Figure(go.Scatter(x=ex, y=ey, mode="lines",
                            line=dict(width=1, color="#334155"), hoverinfo="none"))
            seed_nodes = set(seeds["endpoint"])
            for kind in sorted({d["kind"] for _, d in G.nodes(data=True)}):
                names = [n for n, d in G.nodes(data=True) if d["kind"] == kind]
                fig.add_trace(go.Scatter(
                    x=[pos[n][0] for n in names], y=[pos[n][1] for n in names],
                    mode="markers", name=kind, text=names, hoverinfo="text",
                    marker=dict(size=[20 if n in seed_nodes else 9 for n in names],
                                color=TYPE_COLOR.get(kind, "#64748b"),
                                line=dict(width=1, color="#0b1020"))))
            fig.update_layout(xaxis=dict(visible=False), yaxis=dict(visible=False),
                              legend=dict(orientation="h", y=-0.05))
            st.plotly_chart(style_fig(fig, 620), width="stretch")
            if not g_edges.empty:
                edge_indices = list(range(len(g_edges)))
                selected_edge_index = st.selectbox(
                    "Inspect relationship from graph",
                    edge_indices,
                    format_func=lambda i: (
                        f"{g_edges.iloc[i]['seed_id']} | "
                        f"{g_edges.iloc[i]['s']} ? {g_edges.iloc[i]['t']}"
                    ),
                    key="graph_edge_inspector",
                )
                selected_edge = g_edges.iloc[selected_edge_index]

                detail = q(
                    """SELECT e.edge_id, e.relationship_type, e.status,
                              e.confidence, e.first_seen_utc,
                              e.last_seen_utc, e.evidence_id,
                              r.source_name, r.raw_file_path, r.raw_sha256
                       FROM infrastructure_edges e
                       LEFT JOIN evidence_records r
                         ON r.evidence_id = e.evidence_id
                       WHERE e.edge_id = ?""",
                    (selected_edge["edge_id"],),
                )

                if not detail.empty:
                    st.markdown("**Selected relationship evidence**")
                    show_df(detail)
                    rationale = q(
                        "SELECT rationale FROM infrastructure_edges WHERE edge_id=?",
                        (selected_edge["edge_id"],),
                    )
                    if not rationale.empty:
                        st.markdown("**Analyst rationale**")
                        st.write(rationale.iloc[0, 0])

            st.caption("Large nodes = seeds. Edges are weak candidates, not proof of common control.")

    with tabs[2]:
        st.subheader("Seed inventory")
        view = seeds if selected_seed == "All" else seeds[seeds["seed_id"] == selected_seed]
        cols = st.columns(len(view))
        for col, row in zip(cols, view.itertuples()):
            with col:
                kpi(row.seed_id, row.endpoint, f"{row.evidence_files} evidence · {row.observations} obs", "#22d3ee")
        st.write("")
        show_df(view)

    with tabs[3]:
        st.subheader("Extracted observables")
        nodes = q("""SELECT node_type, value, created_at_utc FROM infrastructure_nodes
                     ORDER BY node_type, value""")
        f1, f2 = st.columns([1, 2])
        with f1:
            sel = st.selectbox("Type", ["All"] + sorted(nodes["node_type"].unique().tolist()))
        with f2:
            term = st.text_input("Search", placeholder="IP, domain, hash...")
        if sel != "All":
            nodes = nodes[nodes["node_type"] == sel]
        if term.strip():
            nodes = nodes[nodes["value"].str.contains(term.strip(), case=False, regex=False)]
        show_df(nodes)

    with tabs[4]:
        st.subheader("Evidence-backed relationships")
        edges = q("""SELECT e.edge_id, sa.seed_id, src.value AS source, tgt.node_type AS target_type,
                            tgt.value AS target, e.relationship_type, e.status, e.confidence,
                            e.first_seen_utc
                     FROM infrastructure_edges e
                     LEFT JOIN infrastructure_nodes src ON src.node_id=e.source_node_id
                     LEFT JOIN infrastructure_nodes tgt ON tgt.node_id=e.target_node_id
                     LEFT JOIN seed_anchors sa ON sa.node_id=e.source_node_id
                     ORDER BY sa.seed_id, e.edge_id""")
        if selected_seed != "All":
            edges = edges[edges["seed_id"] == selected_seed]
        show_df(edges.drop(columns=["edge_id"]) if not edges.empty else edges)
        if not edges.empty:
            eid = st.selectbox("Inspect rationale (edge id)", edges["edge_id"].tolist())
            rat = q("SELECT rationale FROM infrastructure_edges WHERE edge_id=?", (eid,))
            st.markdown(f'<div class="note">{rat.iloc[0, 0]}</div>', unsafe_allow_html=True)

    with tabs[5]:
        st.subheader("Infrastructure clustering")
        run_df = q("""SELECT run_id, algorithm, status, parameters_json FROM cluster_runs
                      ORDER BY started_at_utc DESC, run_id DESC LIMIT 1""")
        if run_df.empty:
            st.info("No clustering run is recorded.")
        else:
            run = run_df.iloc[0]
            params = json.loads(run["parameters_json"])
            m = st.columns(3)
            with m[0]: kpi("Algorithm", run["algorithm"], "heuristic", "#a78bfa")
            with m[1]: kpi("Threshold", params.get("threshold", "—"), "pair score cut-off", "#fbbf24")
            with m[2]: kpi("Status", run["status"], "latest run", "#34d399")
            pairs = q("""SELECT seed_a, seed_b, score, status, shared_observables_json
                         FROM cluster_pair_scores WHERE run_id=? ORDER BY seed_a, seed_b""",
                      (run["run_id"],))
            st.write("")
            show_df(pairs.drop(columns=["shared_observables_json"]) if not pairs.empty else pairs,
                    "No pair scores stored.")
            st.caption("Scores are heuristics, not probabilities. Below-threshold does not mean unrelated.")
            if not pairs.empty:
                labels = (pairs["seed_a"] + " + " + pairs["seed_b"]).tolist()
                pick = st.selectbox("Shared observables for pair", labels)
                st.json(json.loads(pairs.iloc[labels.index(pick)]["shared_observables_json"]))
            st.subheader("Candidate clusters")
            show_df(q("SELECT cluster_id, label, confidence, summary FROM clusters WHERE run_id=?",
                      (run["run_id"],)), "No candidate clusters met the configured threshold.")

    with tabs[6]:
        st.subheader("Collected evidence")
        ev = q("""SELECT evidence_id, seed_id, source_name, evidence_type, raw_file_path,
                         raw_sha256, observed_at_utc FROM evidence_records
                  WHERE seed_id IN ('S001','S002','S003','S004')
                  ORDER BY seed_id, source_name""")
        if selected_seed != "All":
            ev = ev[ev["seed_id"] == selected_seed]
        show_df(ev.drop(columns=["evidence_id"]) if not ev.empty else ev)
        if not ev.empty:
            eid = st.selectbox("Evidence details", ev["evidence_id"].tolist())
            d = q("SELECT details_json FROM evidence_records WHERE evidence_id=?", (eid,))
            with st.expander("Raw evidence details"):
                st.json(json.loads(d.iloc[0, 0]))

    with tabs[7]:
        st.subheader("Download project outputs")
        exports = [
            ("STIX 2.1 bundle", "exports/seeds_s001_s004_stix21.json", "application/json"),
            ("Analysis summary (JSON)", "exports/infrastructure_analysis_summary.json", "application/json"),
            ("SIEM IOC feed (JSON)", "exports/siem_ioc_feed.json", "application/json"),
            ("SIEM IOC feed (CSV)", "exports/siem_ioc_feed.csv", "text/csv"),
            ("Cluster scores (CSV)", "exports/cluster_pair_scores.csv", "text/csv"),
            ("Analysis report (Markdown)", "reports/infrastructure_analysis_report.md", "text/markdown"),
        ]
        cols = st.columns(3)
        for i, (label, rel, mime) in enumerate(exports):
            p = ROOT / rel
            with cols[i % 3]:
                if p.is_file():
                    st.download_button(f"⬇ {label}", p.read_bytes(), p.name, mime,
                                       key=f"dl_{i}", width="stretch")
                else:
                    st.caption(f"Not available yet: {label}")


    with tabs[8]:
        st.subheader("Seed-based pivot workbench")
        st.caption(
            "Search an existing seed IOC or seed ID. "
            "Only direct, evidence-backed relationships are shown."
        )

        with st.form("pivot_workbench_form"):
            pivot_input = st.text_input(
                "Seed IOC or ID",
                placeholder="e.g. 1.14.73.118:34091 or S001",
            )
            submitted = st.form_submit_button(
                "Find related observables", width="stretch"
            )

        if submitted:
            st.session_state["pivot_workbench_query"] = pivot_input.strip()

        query = st.session_state.get("pivot_workbench_query", "")
        if query:
            matched = find_seed(query, DB)
            if matched.empty:
                st.warning(
                    "No exact match found. Enter one of the four existing "
                    "seed IDs or its complete IOC."
                )
            else:
                seed_row = matched.iloc[0]
                seed_id = seed_row["seed_id"]
                st.success(
                    f"Selected {seed_id}: {seed_row['endpoint']}"
                )
                pivots = find_pivots(seed_id, DB)

                if pivots.empty:
                    st.info("No directly linked evidence-backed pivots found.")
                else:
                    m = st.columns(3)
                    with m[0]:
                        st.metric("Direct pivots", pivots["value"].nunique())
                    with m[1]:
                        st.metric("Evidence records", pivots["evidence_id"].nunique())
                    with m[2]:
                        st.metric(
                            "Highest stored score",
                            f"{pivots['pivot_strength'].max():.2f}",
                        )

                    st.caption(
                        "Pivot strength is the existing edge rule score, "
                        "not a probability. It is not an independent "
                        "assessment of maliciousness."
                    )

                    columns = [
                        "node_type", "value", "relationship_type",
                        "status", "pivot_strength", "first_seen_utc",
                        "evidence_id", "source_name",
                    ]
                    st.dataframe(
                        pivots[columns],
                        hide_index=True,
                        width="stretch",
                    )

                    st.markdown("**Inspect pivot evidence**")
                    indices = list(range(len(pivots)))
                    chosen = st.selectbox(
                        "Select an observable",
                        indices,
                        format_func=lambda i: (
                            f"{pivots.iloc[i]['value']} | "
                            f"{pivots.iloc[i]['source_name']} | "
                            f"{pivots.iloc[i]['evidence_id'][-12:]}"
                        ),
                        key="pivot_evidence_selector",
                    )
                    selected = pivots.iloc[chosen]
                    st.write("**Source file:**", selected["raw_file_path"])
                    st.write("**SHA-256:**", selected["raw_sha256"])
                    st.write("**Analyst rationale:**")
                    st.write(selected["rationale"])



    with tabs[9]:
        st.subheader("Source & feed quality")
        st.caption(
            "Metrics reflect the evidence currently stored in the local database. "
            "They do not establish source trustworthiness."
        )

        scope = None if selected_seed == "All" else selected_seed
        quality = get_source_quality(DB, scope)
        coverage = get_source_coverage(DB, scope)

        if quality.empty:
            st.info("No evidence source records are available for this filter.")
        else:
            total_records = int(quality["evidence_records"].sum())
            hash_records = int(quality["sha256_present_records"].sum())
            hash_pct = (
                100.0 * hash_records / total_records
                if total_records else 0.0
            )

            metrics = st.columns(3)
            with metrics[0]:
                st.metric("Observed sources", len(quality))
            with metrics[1]:
                st.metric("Evidence records", total_records)
            with metrics[2]:
                st.metric(
                    "SHA-256 presence",
                    f"{hash_records}/{total_records}",
                    f"{hash_pct:.1f}% of records",
                )

            st.subheader("Evidence volume by source")
            fig = go.Figure(go.Bar(
                x=quality["source_name"].astype(str),
                y=quality["evidence_records"].astype(int),
                marker_color="#7cc7ff",
                hovertemplate="%{x}<br>Evidence records: %{y}<extra></extra>",
            ))
            max_count = max(1, int(quality["evidence_records"].max()))
            fig.update_layout(
                height=320,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#cbd5e1",
                margin=dict(l=10, r=10, t=20, b=10),
                xaxis=dict(title=None),
                yaxis=dict(
                    title="Evidence records",
                    range=[0, max_count + 1],
                    dtick=1,
                ),
            )
            st.plotly_chart(fig, width="stretch")

            st.subheader("Feed metadata completeness")
            st.dataframe(
                quality,
                hide_index=True,
                width="stretch",
            )

            st.subheader("Source coverage by seed")
            st.dataframe(
                coverage,
                hide_index=True,
                width="stretch",
            )

        st.info(
            "Admiralty reliability grades (A?F / 1?6) have not been "
            "configured. Evidence volume, timestamps and hash presence "
            "are feed-quality indicators, not source-reliability ratings."
        )



    with tabs[10]:
        st.subheader("False-link review")
        st.caption(
            "Review weak co-observation candidates. Repeated observables "
            "are review hints, not proof of shared control or false linkage."
        )

        max_score = st.slider(
            "Maximum candidate rule score",
            min_value=0.0,
            max_value=1.0,
            value=0.2,
            step=0.05,
            key="false_link_max_score",
        )
        seed_scope = None if selected_seed == "All" else selected_seed
        review = load_false_link_candidates(DB, seed_scope, max_score)

        if review.empty:
            st.info("No candidates match these filters.")
        else:
            a, b, c = st.columns(3)
            with a:
                st.metric("Review candidates", len(review))
            with b:
                st.metric("Unique observables", review["target_node_id"].nunique())
            with c:
                st.metric(
                    "Repeated across seeds",
                    review.loc[review["seed_overlap"] > 1, "target_node_id"].nunique(),
                )

            st.caption(
                "Changing this filter does not modify database records or "
                "change clustering results."
            )
            st.dataframe(
                review[[
                    "seed_id", "seed_endpoint", "target_type", "target",
                    "seed_overlap", "confidence", "review_hint",
                    "source_name", "evidence_id",
                ]],
                hide_index=True,
                width="stretch",
            )

            choice = st.selectbox(
                "Inspect candidate rationale",
                list(range(len(review))),
                format_func=lambda i: (
                    f"{review.iloc[i]['seed_id']} ? "
                    f"{review.iloc[i]['target']} | "
                    f"{review.iloc[i]['evidence_id'][-12:]}"
                ),
                key="false_link_inspector",
            )
            selected = review.iloc[choice]
            st.write("**Evidence file:**", selected["raw_file_path"])
            st.write("**Analyst rationale:**")
            st.write(selected["rationale"])

        st.info(
            "Persistent shared-infrastructure exclusions and analyst "
            "accept/reject controls are planned; this page is currently "
            "read-only."
        )


except Exception as exc:
    st.error(f"Dashboard data error: {exc}")
