from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_FILE = ROOT / "database" / "intel.db"
CSV_FILE = ROOT / "data" / "seeds" / "seeds.csv"
LOG_FILE = ROOT / "logs" / "build_graph.log"

ALLOWED = ("S001", "S002", "S003", "S004")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str | None, required: bool = False) -> str | None:
    if not value or not value.strip():
        if required:
            raise ValueError("Required timestamp is missing")
        return None
    text = value.strip()
    if text.casefold() == "never":
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def parse_endpoint(raw: str) -> tuple[str, int, str]:
    value = raw.strip()

    if value.startswith("["):
        close = value.find("]")
        if close < 0 or not value[close + 1:].startswith(":"):
            raise ValueError(f"Invalid bracketed endpoint: {raw!r}")
        host = value[1:close]
        port_text = value[close + 2:]
    else:
        host, sep, port_text = value.rpartition(":")
        if not sep or ":" in host:
            raise ValueError(f"Use IP:port or [IPv6]:port: {raw!r}")

    if not port_text.isdigit():
        raise ValueError(f"Invalid port in endpoint: {raw!r}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")

    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast:
        raise ValueError(f"Unexpected IP address: {host}")

    normalized_ip = address.compressed
    normalized = (
        f"[{normalized_ip}]:{port}"
        if address.version == 6
        else f"{normalized_ip}:{port}"
    )
    return normalized_ip, port, normalized


def merge_endpoint_attributes(existing_json: str, expected: dict) -> str:
    """Merge canonical endpoint fields without discarding extraction provenance.

    Unknown or additional attributes (for example ``field_path`` and
    shared-infrastructure annotations) are preserved. A conflicting known,
    non-null canonical value still fails closed.
    """
    try:
        current = json.loads(existing_json or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Existing endpoint attributes are not valid JSON") from exc
    if not isinstance(current, dict):
        raise ValueError("Existing endpoint attributes must be a JSON object")

    for key, expected_value in expected.items():
        if key not in current or current[key] is None:
            if expected_value is not None:
                current[key] = expected_value
            else:
                current.setdefault(key, None)
        elif expected_value is not None and current[key] != expected_value:
            raise ValueError(
                f"Conflicting infrastructure node attribute {key}: "
                f"existing={current[key]!r}, expected={expected_value!r}"
            )

    return json.dumps(current, sort_keys=True, ensure_ascii=False)


def seed_id_from_indicator(obj: dict) -> str | None:
    if obj.get("type") != "indicator":
        return None

    ids = [
        str(ref.get("external_id", "")).strip().upper()
        for ref in obj.get("external_references", [])
        if isinstance(ref, dict)
        and str(ref.get("external_id", "")).strip().upper().startswith("S")
    ]

    if not ids:
        raise ValueError(f"Indicator {obj.get('id')} has no seed ID")
    if len(ids) != 1:
        raise ValueError(f"Indicator {obj.get('id')} has ambiguous seed IDs")
    if ids[0] not in ALLOWED:
        raise ValueError(f"Out-of-scope seed rejected: {ids[0]}")
    return ids[0]


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS infrastructure_nodes (
        node_id TEXT PRIMARY KEY,
        node_type TEXT NOT NULL,
        value TEXT NOT NULL,
        normalized_value TEXT NOT NULL,
        attributes_json TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(node_type, normalized_value)
    );

    CREATE TABLE IF NOT EXISTS seed_anchors (
        seed_id TEXT PRIMARY KEY
            CHECK(seed_id IN ('S001','S002','S003','S004')),
        node_id TEXT NOT NULL REFERENCES infrastructure_nodes(node_id),
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT,
        observed_at_utc TEXT,
        source TEXT NOT NULL,
        source_reference TEXT,
        metadata_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence_records (
        evidence_id TEXT PRIMARY KEY,
        seed_id TEXT
            CHECK(seed_id IS NULL OR seed_id IN ('S001','S002','S003','S004')),
        source_name TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        source_reference TEXT,
        raw_file_path TEXT,
        raw_sha256 TEXT,
        observed_at_utc TEXT,
        details_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS infrastructure_edges (
        edge_id TEXT PRIMARY KEY,
        source_node_id TEXT NOT NULL
            REFERENCES infrastructure_nodes(node_id),
        target_node_id TEXT NOT NULL
            REFERENCES infrastructure_nodes(node_id),
        relationship_type TEXT NOT NULL,
        first_seen_utc TEXT,
        last_seen_utc TEXT,
        confidence REAL NOT NULL
            CHECK(confidence >= 0 AND confidence <= 1),
        evidence_id TEXT NOT NULL
            REFERENCES evidence_records(evidence_id),
        status TEXT NOT NULL DEFAULT 'candidate'
            CHECK(status IN ('candidate','confirmed','rejected')),
        rationale TEXT NOT NULL,
        CHECK(source_node_id <> target_node_id)
    );

    CREATE INDEX IF NOT EXISTS idx_edges_source
        ON infrastructure_edges(source_node_id);
    CREATE INDEX IF NOT EXISTS idx_edges_target
        ON infrastructure_edges(target_node_id);
    CREATE INDEX IF NOT EXISTS idx_edges_status
        ON infrastructure_edges(status);

    CREATE TABLE IF NOT EXISTS cluster_runs (
        run_id TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at_utc TEXT NOT NULL,
        completed_at_utc TEXT
    );

    CREATE TABLE IF NOT EXISTS clusters (
        cluster_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES cluster_runs(run_id),
        label TEXT NOT NULL,
        confidence REAL CHECK(
            confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
        ),
        summary TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cluster_memberships (
        cluster_id TEXT NOT NULL REFERENCES clusters(cluster_id),
        node_id TEXT NOT NULL REFERENCES infrastructure_nodes(node_id),
        membership_type TEXT NOT NULL DEFAULT 'candidate',
        PRIMARY KEY(cluster_id, node_id)
    );
    """)
    conn.commit()


def import_seed_graph(
    conn: sqlite3.Connection,
    rows: list[dict],
    objects: list[dict],
) -> tuple[int, int]:
    csv_by_seed = {}
    for row in rows:
        seed_id = (row.get("seed_id") or "").strip().upper()
        if not seed_id:
            raise ValueError("A CSV row is missing seed_id")
        if seed_id not in ALLOWED:
            continue
        if seed_id in csv_by_seed:
            raise ValueError(f"Duplicate CSV seed: {seed_id}")
        csv_by_seed[seed_id] = row

    indicators = {}
    for obj in objects:
        seed_id = seed_id_from_indicator(obj)
        if seed_id is None:
            continue
        if seed_id in indicators:
            raise ValueError(f"Duplicate STIX indicator for {seed_id}")
        indicators[seed_id] = obj

    missing_csv = set(ALLOWED) - set(csv_by_seed)
    missing_stix = set(ALLOWED) - set(indicators)
    if missing_csv or missing_stix:
        raise ValueError(
            f"Missing CSV seeds: {sorted(missing_csv)}; "
            f"missing STIX indicators: {sorted(missing_stix)}"
        )

    nodes_added = 0
    anchors_added = 0

    with conn:
        for seed_id in ALLOWED:
            row = csv_by_seed[seed_id]
            obj = indicators[seed_id]
            raw_ioc = (row.get("ioc") or "").strip()
            if not raw_ioc:
                raise ValueError(f"{seed_id}: IOC is empty")

            ip, port, normalized = parse_endpoint(raw_ioc)
            node_id = "endpoint--" + hashlib.sha256(
                normalized.encode("utf-8")
            ).hexdigest()

            ip_version = ipaddress.ip_address(ip).version
            attributes = {
                "ip_address": ip,
                "ip_version": ip_version,
                "port": port,
                "transport": None,
                "original_ioc": raw_ioc,
            }
            attributes_json = json.dumps(
                attributes, sort_keys=True, ensure_ascii=False
            )
            node_values = (
                "network-endpoint", normalized, normalized, attributes_json
            )

            existing = conn.execute(
                """SELECT node_type, value, normalized_value, attributes_json
                   FROM infrastructure_nodes WHERE node_id = ?""",
                (node_id,),
            ).fetchone()

            if existing is None:
                conn.execute(
                    """INSERT INTO infrastructure_nodes
                       (node_id,node_type,value,normalized_value,
                        attributes_json,created_at_utc)
                       VALUES (?,?,?,?,?,?)""",
                    (node_id, *node_values, utc_now()),
                )
                nodes_added += 1
            else:
                if tuple(existing[:3]) != node_values[:3]:
                    raise ValueError(f"Conflicting infrastructure node identity: {node_id}")
                merged_attributes = merge_endpoint_attributes(existing[3], attributes)
                if merged_attributes != existing[3]:
                    conn.execute(
                        "UPDATE infrastructure_nodes SET attributes_json=? WHERE node_id=?",
                        (merged_attributes, node_id),
                    )

            first_seen = parse_timestamp(obj.get("valid_from"), required=True)
            last_seen = parse_timestamp(row.get("last_seen_utc"))
            observed = parse_timestamp(row.get("observed_at_utc"))
            source = (row.get("source") or "unknown").strip()
            reference = (row.get("source_reference") or "").strip() or None
            metadata = json.dumps(
                row, sort_keys=True, ensure_ascii=False
            )

            anchor_values = (
                node_id, first_seen, last_seen, observed,
                source, reference, metadata,
            )
            existing_anchor = conn.execute(
                """SELECT node_id,first_seen_utc,last_seen_utc,
                          observed_at_utc,source,source_reference,metadata_json
                   FROM seed_anchors WHERE seed_id = ?""",
                (seed_id,),
            ).fetchone()

            if existing_anchor is None:
                conn.execute(
                    """INSERT INTO seed_anchors
                       (seed_id,node_id,first_seen_utc,last_seen_utc,
                        observed_at_utc,source,source_reference,metadata_json)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (seed_id, *anchor_values),
                )
                anchors_added += 1
            elif tuple(existing_anchor) != anchor_values:
                raise ValueError(f"Conflicting seed anchor: {seed_id}")

    return nodes_added, anchors_added


def main() -> int:
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        if not CSV_FILE.is_file() or not DB_FILE.is_file():
            raise FileNotFoundError("Seed CSV or STIX database is missing")

        with CSV_FILE.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))

        bundle_rows = json.loads(
            DB_FILE.read_text(encoding="utf-8")
        ) if False else None

        with sqlite3.connect(str(DB_FILE), timeout=30) as conn:
            initialize_schema(conn)
            stix_rows = conn.execute(
                "SELECT object_json FROM stix_objects WHERE object_type = 'indicator'"
            ).fetchall()
            objects = [json.loads(row[0]) for row in stix_rows]
            nodes, anchors = import_seed_graph(conn, rows, objects)
            node_count = conn.execute(
                "SELECT COUNT(*) FROM infrastructure_nodes"
            ).fetchone()[0]
            anchor_count = conn.execute(
                "SELECT COUNT(*) FROM seed_anchors"
            ).fetchone()[0]
            edge_count = conn.execute(
                "SELECT COUNT(*) FROM infrastructure_edges"
            ).fetchone()[0]

        logging.info(
            "Graph initialized; nodes_added=%d anchors_added=%d",
            nodes, anchors
        )
        print(f"Database: {DB_FILE}")
        print(f"New infrastructure nodes: {nodes}")
        print(f"New seed anchors: {anchors}")
        print(f"Total infrastructure nodes: {node_count}")
        print(f"Total seed anchors: {anchor_count}")
        print(f"Evidence-backed edges: {edge_count}")
        print("Seed scope: S001, S002, S003, S004")
        return 0
    except Exception as exc:
        logging.exception("Graph initialization failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
