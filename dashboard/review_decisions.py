from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from dashboard.data_access import DEFAULT_DB, open_readonly

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REVIEW_FILE = ROOT / "data" / "review" / "edge_review_decisions.json"

ALLOWED_DECISIONS = ("needs_review", "accepted", "rejected")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def empty_state() -> dict:
    return {
        "schema_version": 1,
        "updated_at_utc": None,
        "decisions": {},
        "history": [],
    }


def load_decisions(review_file=DEFAULT_REVIEW_FILE) -> dict:
    path = Path(review_file)
    if not path.exists():
        return empty_state()

    try:
        state = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read review decisions: {exc}") from exc

    if not isinstance(state, dict) or state.get("schema_version") != 1:
        raise ValueError("Unsupported review decision file format")

    if not isinstance(state.get("decisions"), dict):
        raise ValueError("Review decisions must be a JSON object")

    if not isinstance(state.get("history"), list):
        raise ValueError("Review history must be a JSON array")

    for edge_id, item in state["decisions"].items():
        if not isinstance(item, dict):
            raise ValueError(f"Invalid review entry for {edge_id}")
        if item.get("decision") not in ALLOWED_DECISIONS:
            raise ValueError(f"Invalid saved decision for {edge_id}")

    return state


def save_decision(
    edge_id: str,
    decision: str,
    reviewer: str,
    reason: str,
    review_file=DEFAULT_REVIEW_FILE,
    database=DEFAULT_DB,
) -> dict:
    edge_id = str(edge_id).strip()
    decision = str(decision).strip()
    reviewer = str(reviewer).strip()
    reason = str(reason).strip()

    if not edge_id or len(edge_id) > 256:
        raise ValueError("Invalid edge ID")
    if decision not in ALLOWED_DECISIONS:
        raise ValueError("Choose a valid analyst decision")
    if not reviewer or len(reviewer) > 80:
        raise ValueError("Reviewer label must contain 1–80 characters")
    if not 5 <= len(reason) <= 2000:
        raise ValueError("Reason must contain 5–2000 characters")

    connection = open_readonly(Path(database))
    try:
        edge = connection.execute(
            """SELECT status, relationship_type
               FROM infrastructure_edges WHERE edge_id = ?""",
            (edge_id,),
        ).fetchone()
    finally:
        connection.close()

    if edge is None:
        raise ValueError("Relationship does not exist in the database")
    if edge[0] != "candidate":
        raise ValueError("Only candidate relationships can be reviewed")
    if edge[1] != "co-observed-in-evidence":
        raise ValueError("Unsupported relationship type for review")

    path = Path(review_file)
    state = load_decisions(path)
    previous = state["decisions"].get(edge_id)
    previous_decision = previous.get("decision") if previous else None
    reviewed_at = utc_now()

    event_material = json.dumps(
        {
            "edge_id": edge_id,
            "decision": decision,
            "reviewer": reviewer,
            "reason": reason,
            "reviewed_at_utc": reviewed_at,
            "history_length": len(state["history"]),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    event_id = "review-event--" + hashlib.sha256(
        event_material.encode("utf-8")
    ).hexdigest()

    entry = {
        "decision": decision,
        "reviewer": reviewer,
        "reason": reason,
        "reviewed_at_utc": reviewed_at,
        "event_id": event_id,
    }

    state["history"].append({
        "edge_id": edge_id,
        "previous_decision": previous_decision,
        **entry,
    })
    state["decisions"][edge_id] = entry
    state["updated_at_utc"] = reviewed_at

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return entry
