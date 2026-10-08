import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_graph import import_seed_graph, initialize_schema, parse_endpoint


def _seed_data():
    rows = [
        {"seed_id": "S001", "ioc": "1.14.73.118:34091"},
        {"seed_id": "S002", "ioc": "101.42.108.164:31337"},
        {"seed_id": "S003", "ioc": "103.250.172.230:31337"},
        {"seed_id": "S004", "ioc": "103.253.42.61:31337"},
    ]
    indicators = [
        {
            "type": "indicator",
            "id": f"indicator--{seed.lower()}",
            "valid_from": "2026-09-01T00:00:00Z",
            "external_references": [{"external_id": seed}],
        }
        for seed in ("S001", "S002", "S003", "S004")
    ]
    return rows, indicators


def _endpoint_node(ioc):
    ip, port, normalized = parse_endpoint(ioc)
    node_id = "endpoint--" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    attrs = {
        "ip_address": ip,
        "ip_version": 4,
        "port": port,
        "transport": None,
        "original_ioc": ioc,
    }
    return node_id, normalized, attrs


def test_graph_import_preserves_extraction_attributes():
    conn = sqlite3.connect(":memory:")
    initialize_schema(conn)
    node_id, normalized, attrs = _endpoint_node("1.14.73.118:34091")
    attrs["field_path"] = ["contacted_ips[0].ip"]
    attrs["is_shared_infrastructure"] = False
    conn.execute(
        """INSERT INTO infrastructure_nodes
           (node_id,node_type,value,normalized_value,attributes_json,created_at_utc)
           VALUES(?,?,?,?,?,?)""",
        (node_id, "network-endpoint", normalized, normalized,
         json.dumps(attrs, sort_keys=True), "2026-09-01T00:00:00Z"),
    )

    added, anchors = import_seed_graph(conn, *_seed_data())

    saved = json.loads(conn.execute(
        "SELECT attributes_json FROM infrastructure_nodes WHERE node_id=?", (node_id,)
    ).fetchone()[0])
    assert saved["field_path"] == ["contacted_ips[0].ip"]
    assert saved["is_shared_infrastructure"] is False
    assert added == 3
    assert anchors == 4
    assert conn.execute("SELECT COUNT(*) FROM seed_anchors").fetchone()[0] == 4
    conn.close()


def test_graph_import_still_rejects_conflicting_canonical_endpoint_data():
    conn = sqlite3.connect(":memory:")
    initialize_schema(conn)
    node_id, normalized, attrs = _endpoint_node("1.14.73.118:34091")
    attrs["port"] = 31337
    conn.execute(
        """INSERT INTO infrastructure_nodes
           (node_id,node_type,value,normalized_value,attributes_json,created_at_utc)
           VALUES(?,?,?,?,?,?)""",
        (node_id, "network-endpoint", normalized, normalized,
         json.dumps(attrs, sort_keys=True), "2026-09-01T00:00:00Z"),
    )

    with pytest.raises(ValueError, match="Conflicting infrastructure node attribute port"):
        import_seed_graph(conn, *_seed_data())
    assert conn.execute("SELECT COUNT(*) FROM seed_anchors").fetchone()[0] == 0
    conn.close()
