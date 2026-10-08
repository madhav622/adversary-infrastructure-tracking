import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cleanup_test_records import cleanup_test_records, restore_test_records, KNOWN_TEST_REASONS


def _fixture(tmp_path):
    db = tmp_path / "intel.db"
    review = tmp_path / "edge_review_decisions.json"
    archive = tmp_path / "archive"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
        CREATE TABLE alert_records (alert_id TEXT PRIMARY KEY);
        CREATE TABLE alert_triage_history (
            history_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL,
            previous_status TEXT NOT NULL, new_status TEXT NOT NULL,
            previous_severity TEXT NOT NULL, new_severity TEXT NOT NULL,
            reviewer TEXT NOT NULL, reason TEXT NOT NULL, changed_at_utc TEXT NOT NULL
        );
        INSERT INTO alert_records VALUES ('a1');
        INSERT INTO alert_triage_history VALUES
          ('h-test-1','a1','new','triaged','low','low','analyst','Manual triage testing completed','2026-09-30T00:00:00Z'),
          ('h-test-2','a1','new','triaged','low','low','analyst','Alert reviewed and triaged for testing','2026-09-30T00:00:01Z'),
          ('h-good','a1','new','triaged','low','medium','analyst','Reviewed source evidence and assessed relevance','2026-09-30T00:00:02Z');
        """)
    payload = {
        "schema_version": 1,
        "updated_at_utc": "2026-09-30T00:00:00Z",
        "decisions": {
            "edge-test": {"decision": "needs_review", "reason": "Pending manual verification. Testing analyst decision persistence."},
            "edge-good": {"decision": "needs_review", "reason": "Needs independent corroboration before promotion."},
        },
        "history": [
            {"edge_id": "edge-test", "reason": "Review reason"},
            {"edge_id": "edge-test", "reason": "Pending manual verification. Testing analyst decision persistence."},
            {"edge_id": "edge-good", "reason": "Needs independent corroboration before promotion."},
        ],
    }
    review.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return db, review, archive


def test_cleanup_archives_and_removes_exact_test_records(tmp_path):
    db, review, archive_dir = _fixture(tmp_path)
    result = cleanup_test_records(db, review, archive_dir)
    assert result["changed"] is True
    assert result["database_rows"] == 2
    assert result["review_decisions"] == 1
    assert result["review_history"] == 2
    assert Path(result["archive"]).is_file()
    archive_payload = json.loads(Path(result["archive"]).read_text(encoding="utf-8"))
    snapshot = Path(result["archive"]).with_name(archive_payload["database_backup_file"])
    assert snapshot.is_file()
    assert archive_payload["database_backup_sha256"] == __import__("hashlib").sha256(snapshot.read_bytes()).hexdigest()
    with sqlite3.connect(db) as conn:
        reasons = [row[0] for row in conn.execute("SELECT reason FROM alert_triage_history")]
    assert reasons == ["Reviewed source evidence and assessed relevance"]
    cleaned = json.loads(review.read_text(encoding="utf-8"))
    assert set(cleaned["decisions"]) == {"edge-good"}
    assert len(cleaned["history"]) == 1


def test_cleanup_is_idempotent(tmp_path):
    db, review, archive_dir = _fixture(tmp_path)
    first = cleanup_test_records(db, review, archive_dir)
    second = cleanup_test_records(db, review, archive_dir)
    assert first["changed"] is True
    assert second["changed"] is False
    assert len(list(archive_dir.glob("cleanup_*.json"))) == 1


def test_restore_reverses_cleanup(tmp_path):
    db, review, archive_dir = _fixture(tmp_path)
    original_review = review.read_bytes()
    result = cleanup_test_records(db, review, archive_dir)
    restored = restore_test_records(result["archive"], db, review)
    assert restored["restored_database_rows"] == 2
    assert restored["restored_review_decisions"] == 1
    assert restored["restored_review_history"] == 2
    assert review.read_bytes() == original_review
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM alert_triage_history").fetchone()[0] == 3


def test_restore_refuses_to_overwrite_new_review_edits(tmp_path):
    db, review, archive_dir = _fixture(tmp_path)
    result = cleanup_test_records(db, review, archive_dir)
    review.write_text('{"new_analyst_edit": true}', encoding="utf-8")
    try:
        restore_test_records(result["archive"], db, review)
    except ValueError as exc:
        assert "refusing to overwrite" in str(exc)
    else:
        raise AssertionError("Restore should refuse to overwrite analyst edits")
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM alert_triage_history").fetchone()[0] == 1


def test_project_database_and_review_have_no_known_test_reasons():
    db = ROOT / "database" / "intel.db"
    review = ROOT / "data" / "review" / "edge_review_decisions.json"
    if db.is_file():
        with sqlite3.connect(db) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(alert_triage_history)")]
            if "reason" in columns:
                reasons = [row[0] for row in conn.execute("SELECT reason FROM alert_triage_history")]
                assert not any(" ".join(str(reason or "").casefold().split()) in KNOWN_TEST_REASONS for reason in reasons)
    if review.is_file():
        payload = json.loads(review.read_text(encoding="utf-8-sig"))
        records = list(payload.get("decisions", {}).values()) + list(payload.get("history", []))
        assert not any(
            isinstance(record, dict) and " ".join(str(record.get("reason") or "").casefold().split()) in KNOWN_TEST_REASONS
            for record in records
        )
