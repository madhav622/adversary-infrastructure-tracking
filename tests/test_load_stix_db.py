import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from normalize_stix import normalize_rows
from load_stix_db import load_bundle


def make_bundle():
    rows = [
        {
            "seed_id": "S001",
            "ioc": "1.14.73.118:34091",
            "first_seen_utc": "2026-09-05T11:35:01Z",
            "source": "ThreatFox",
        },
        {
            "seed_id": "S002",
            "ioc": "101.42.108.164:31337",
            "first_seen_utc": "2026-09-27T00:00:00Z",
            "source": "ThreatFox",
        },
        {
            "seed_id": "S003",
            "ioc": "103.250.172.230:31337",
            "first_seen_utc": "2026-09-02T00:00:00Z",
            "source": "ThreatFox",
        },
        {
            "seed_id": "S004",
            "ioc": "103.253.42.61:31337",
            "first_seen_utc": "2026-09-14T00:00:00Z",
            "source": "ThreatFox",
        },
    ]
    return normalize_rows(rows)


def test_load_bundle_and_idempotence(tmp_path):
    bundle_file = tmp_path / "bundle.json"
    db_file = tmp_path / "intel.db"
    bundle_file.write_text(make_bundle().serialize(), encoding="utf-8")

    inserted, total = load_bundle(bundle_file, db_file)
    assert inserted == 5
    assert total == 5

    inserted_again, total_again = load_bundle(bundle_file, db_file)
    assert inserted_again == 0
    assert total_again == 5


def test_rejects_out_of_scope_seed(tmp_path):
    bundle_file = tmp_path / "bundle.json"
    db_file = tmp_path / "intel.db"
    data = json.loads(make_bundle().serialize())

    for obj in data["objects"]:
        if obj["type"] == "indicator":
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == "S001":
                    ref["external_id"] = "S005"

    bundle_file.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="Out-of-scope seed"):
        load_bundle(bundle_file, db_file)


def test_rejects_incomplete_bundle(tmp_path):
    bundle_file = tmp_path / "bundle.json"
    db_file = tmp_path / "intel.db"
    data = json.loads(make_bundle().serialize())
    data["objects"] = [
        obj for obj in data["objects"]
        if not (
            obj["type"] == "indicator"
            and any(
                ref.get("external_id") == "S004"
                for ref in obj.get("external_references", [])
            )
        )
    ]
    bundle_file.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="Missing seed indicators"):
        load_bundle(bundle_file, db_file)
