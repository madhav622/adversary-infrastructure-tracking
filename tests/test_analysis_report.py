import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_analysis_report import render_report, atomic_write


def test_report_contains_scope_and_limitations():
    data = {
        "generated_at_utc": "2026-09-30T12:00:00Z",
        "scope": ["S001", "S002", "S003", "S004"],
        "totals": {
            "stix_objects": 5,
            "infrastructure_nodes": 46,
            "seed_anchors": 4,
            "evidence_records": 12,
            "entity_observations": 73,
            "infrastructure_edges": 49,
            "cluster_runs": 1,
            "clusters": 0,
            "cluster_memberships": 0,
        },
        "seeds": [],
        "node_types": [],
        "edge_statuses": [{"status": "candidate", "count": 49}],
        "latest_run": {
            "run_id": "test-run",
            "algorithm": "test",
            "parameters": {"threshold": 0.5},
            "status": "completed",
            "candidate_clusters": 0,
        },
        "pair_scores": [{
            "seed_a": "S001",
            "seed_b": "S002",
            "score": 0.0,
            "status": "below_threshold",
            "shared_count": 0,
            "shared": [],
        }],
    }

    report = render_report(data)
    assert "S001, S002, S003, S004" in report
    assert "S005 is excluded" in report
    assert "not probabilities" in report
    assert "does not establish that the seed infrastructures are unrelated" in report


def test_atomic_write(tmp_path):
    target = tmp_path / "report.md"
    atomic_write(target, "# Test report\n")
    assert target.read_text(encoding="utf-8") == "# Test report\n"
    assert not target.with_suffix(".md.tmp").exists()


def test_json_summary_is_serializable():
    data = {"scope": ["S001", "S002", "S003", "S004"]}
    assert json.loads(json.dumps(data)) == data
