import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.review_decisions import load_decisions, save_decision


def make_db(path, status="candidate", rel_type="co-observed-in-evidence"):
    with sqlite3.connect(path) as conn:
        conn.execute("""
            CREATE TABLE infrastructure_edges (
                edge_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                relationship_type TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO infrastructure_edges VALUES (?,?,?)",
            ("edge-test", status, rel_type),
        )


def test_new_review_file_is_empty(tmp_path):
    path = tmp_path / "decisions.json"
    state = load_decisions(path)
    assert state["schema_version"] == 1
    assert state["decisions"] == {}
    assert state["history"] == []


def test_saves_and_updates_a_decision(tmp_path):
    db = tmp_path / "intel.db"
    path = tmp_path / "decisions.json"
    make_db(db)

    first = save_decision(
        "edge-test", "accepted", "analyst",
        "Evidence reviewed and plausible.", path, db
    )
    second = save_decision(
        "edge-test", "rejected", "analyst",
        "Reassessment found insufficient linkage.", path, db
    )

    state = load_decisions(path)
    assert state["decisions"]["edge-test"]["decision"] == "rejected"
    assert second["event_id"] != first["event_id"]
    assert len(state["history"]) == 2
    assert state["history"][1]["previous_decision"] == "accepted"


def test_rejects_unknown_edge(tmp_path):
    db = tmp_path / "intel.db"
    path = tmp_path / "decisions.json"
    make_db(db)

    with pytest.raises(ValueError, match="does not exist"):
        save_decision(
            "missing", "accepted", "analyst",
            "Reviewed evidence.", path, db
        )


def test_rejects_non_candidate_edge(tmp_path):
    db = tmp_path / "intel.db"
    path = tmp_path / "decisions.json"
    make_db(db, status="rejected")

    with pytest.raises(ValueError, match="Only candidate"):
        save_decision(
            "edge-test", "accepted", "analyst",
            "Reviewed evidence.", path, db
        )


def test_rejects_invalid_decision_or_reason(tmp_path):
    db = tmp_path / "intel.db"
    path = tmp_path / "decisions.json"
    make_db(db)

    with pytest.raises(ValueError, match="valid analyst decision"):
        save_decision(
            "edge-test", "confirmed", "analyst",
            "Reviewed evidence.", path, db
        )

    with pytest.raises(ValueError, match="5–2000"):
        save_decision(
            "edge-test", "rejected", "analyst",
            "No", path, db
        )


def test_corrupt_review_file_is_not_overwritten(tmp_path):
    db = tmp_path / "intel.db"
    path = tmp_path / "decisions.json"
    make_db(db)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="Cannot read"):
        save_decision(
            "edge-test", "rejected", "analyst",
            "Evidence insufficient.", path, db
        )

    assert path.read_text(encoding="utf-8") == "{broken"
