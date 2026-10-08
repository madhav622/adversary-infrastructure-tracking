import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from import_raw_evidence import import_evidence


def test_imports_scoped_files_and_is_idempotent(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    db = tmp_path / "intel.db"

    (raw / "S001_test_20260930.json").write_text(
        '{"source":"VirusTotal","observed_at_utc":"2026-09-30T00:00:00Z"}',
        encoding="utf-8",
    )
    (raw / "S005_details_20260930.json").write_text(
        '{"ignored":true}', encoding="utf-8"
    )
    (raw / "S001_S004_manifest_20260930.json").write_text(
        '{"manifest":true}', encoding="utf-8"
    )

    inserted, total, counts = import_evidence(raw, db)
    assert inserted == 1
    assert total == 1
    assert counts["S001"] == 1
    assert counts["S002"] == 0

    inserted_again, total_again, _ = import_evidence(raw, db)
    assert inserted_again == 0
    assert total_again == 1


def test_invalid_json_is_rejected(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    db = tmp_path / "intel.db"
    (raw / "S002_invalid.json").write_text(
        "{not valid json", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Invalid JSON"):
        import_evidence(raw, db)
