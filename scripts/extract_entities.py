from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

from entity_validation import (
    ROOT as VALIDATION_ROOT,
    SHARED_INFRA_FILE,
    domain_validation_reason,
    load_shared_infrastructure,
    registrable_domain,
    shared_infrastructure_match,
    validate_public_ip,
)

ROOT = Path(__file__).resolve().parents[1]
DB_FILE = ROOT / "database" / "intel.db"
LOG_FILE = ROOT / "logs" / "extract_entities.log"
SEEDS = ("S001", "S002", "S003", "S004")
EXTRACTION_METHOD = "passive-evidence-v2"

RANGE_FIELDS = {
    "inetnum", "cidr", "netblock", "netblocks", "subnet",
    "subnet_range", "network_range", "ip_range", "ipv4_range",
    "ipv6_range", "address_range", "route", "network",
    "start_ip", "end_ip", "start_address", "end_address",
    "broadcast_address", "network_address",
}
METADATA_FIELDS = {
    "vendor", "vendors", "engine", "engines", "popular_threat_label",
    "threat_label", "malware_label", "malware_family", "threat_family",
    "detection", "detections", "family_labels", "threat_categories",
}
FILENAME_FIELDS = {"filename", "file_name", "basename"}
IP_CONTEXTS = {
    "contacted_ips", "passive_dns", "dns_records", "dns", "resolutions",
    "resolved_ips", "subdomains", "records", "answers", "ips",
}
DOMAIN_FIELDS = {"domain", "domain_name", "hostname", "host_name", "fqdn", "dns_name"}
HASH_FIELDS = {
    "md5", "sha1", "sha256", "file_md5", "file_sha1", "file_sha256",
    "parent_file_sha256", "thumbprint", "fingerprint",
    "certificate_fingerprint", "cert_fingerprint",
}


def _segments(path: str) -> list[str]:
    return [
        part.casefold()
        for part in re.split(r"[.\[\]]+", path)
        if part and not part.isdigit()
    ]


def iter_strings(value, path=""):
    """Compatibility iterator that preserves structured field provenance."""
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_strings(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_strings(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _in_context(parts: list[str], contexts: set[str]) -> bool:
    return bool(set(parts[:-1]).intersection(contexts))


def _is_metadata_or_file(parts: list[str]) -> bool:
    return bool(set(parts).intersection(METADATA_FIELDS | FILENAME_FIELDS))


def _hash_entity(value: object, path: str):
    if not isinstance(value, str):
        return None
    text = value.strip().casefold()
    if not re.fullmatch(r"[0-9a-f]+", text):
        return None
    parts = _segments(path)
    leaf = parts[-1] if parts else ""
    cert_context = bool(set(parts[:-1]).intersection({"certificate", "certificates", "ssl_certificates"}))
    if leaf in {"thumbprint", "fingerprint", "certificate_fingerprint", "cert_fingerprint"} or (cert_context and leaf == "sha256"):
        if len(text) in (40, 64):
            return "certificate-fingerprint", text
        return None
    if len(text) == 32:
        return "file-hash-md5", text
    if len(text) == 40:
        return "file-hash-sha1", text
    if len(text) == 64:
        return "file-hash-sha256", text
    return None


def _certificate_names(value: str):
    text = value.strip()
    if text.casefold().startswith("dns:"):
        yield "domain-name", text[4:].strip()
    elif text.casefold().startswith("ip address:"):
        yield "ip-address", text.split(":", 1)[1].strip()


def _subject_common_names(value: str):
    for match in re.finditer(r"(?:^|[,/])\s*CN\s*=\s*([^,/]+)", value, re.IGNORECASE):
        yield match.group(1).strip()


def _iter_candidates(payload: dict | list):
    for path, value in iter_strings(payload):
        parts = _segments(path)
        if not parts or not isinstance(value, str):
            continue
        leaf = parts[-1]
        if _is_metadata_or_file(parts):
            continue

        if leaf in DOMAIN_FIELDS:
            yield "domain-name", value.strip(), path
        elif leaf == "name" and _in_context(parts, {"subdomains", "dns_records", "dns", "dns_names"}):
            yield "domain-name", value.strip(), path
        elif leaf in {"ip", "ip_address", "ipv4", "ipv6"}:
            if len(parts) == 1 or _in_context(parts, IP_CONTEXTS):
                yield "ip-address", value.strip(), path
        elif leaf == "ips" and _in_context(parts, {"subdomains", "dns_records", "dns"}):
            yield "ip-address", value.strip(), path
        elif leaf == "san" or leaf == "sans":
            for kind, candidate in _certificate_names(value):
                yield kind, candidate, path
        elif leaf == "subject" and set(parts[:-1]).intersection({"certificate", "certificates", "ssl_certificates"}):
            for candidate in _subject_common_names(value):
                yield "domain-name", candidate, path

        if leaf in HASH_FIELDS:
            entity = _hash_entity(value, path)
            if entity:
                yield entity[0], entity[1], path


def _validated_entities(payload: dict | list, shared_entries: list[dict]):
    entities: dict[tuple[str, str], dict] = {}
    for raw_kind, raw_value, field_path in _iter_candidates(payload):
        if raw_kind == "domain-name":
            reason = domain_validation_reason(raw_value)
            value = raw_value.strip().rstrip(".").casefold()
            if reason:
                continue
            registrable = registrable_domain(value)
            kind = "domain-name"
            shared = None
        elif raw_kind == "ip-address":
            value, reason = validate_public_ip(raw_value)
            if reason:
                continue
            kind = "ipv4-addr" if ipaddress.ip_address(value).version == 4 else "ipv6-addr"
            registrable = None
            shared = shared_infrastructure_match(value, shared_entries)
        else:
            kind, value = raw_kind, raw_value
            registrable = None
            shared = None

        item = entities.setdefault((kind, value), {"field_paths": set()})
        item["field_paths"].add(field_path)
        if registrable:
            item["registrable_domain"] = registrable
        if shared:
            item["shared"] = shared
    return entities


def extract_from_payload(payload: dict | list) -> list[tuple[str, str, str]]:
    """Extract only typed observables from explicitly supported evidence fields."""
    if not isinstance(payload, (dict, list)):
        return []
    entries = load_shared_infrastructure(SHARED_INFRA_FILE)
    entities = _validated_entities(payload, entries)
    return sorted(
        (kind, value, field_path)
        for (kind, value), item in entities.items()
        for field_path in item["field_paths"]
    )


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, definition: str):
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def ensure_lifecycle_schema(conn: sqlite3.Connection):
    if _table_exists(conn, "infrastructure_nodes"):
        _ensure_column(conn, "infrastructure_nodes", "lifecycle_status", "TEXT NOT NULL DEFAULT 'active' CHECK(lifecycle_status IN ('active','retired'))")
        _ensure_column(conn, "infrastructure_nodes", "retirement_reason", "TEXT")
    if _table_exists(conn, "infrastructure_edges"):
        _ensure_column(conn, "infrastructure_edges", "lifecycle_status", "TEXT NOT NULL DEFAULT 'active' CHECK(lifecycle_status IN ('active','retired'))")
        _ensure_column(conn, "infrastructure_edges", "retirement_reason", "TEXT")
    if _table_exists(conn, "alert_records"):
        _ensure_column(conn, "alert_records", "eligibility", "TEXT NOT NULL DEFAULT 'unverified' CHECK(eligibility IN ('eligible','excluded','unverified'))")
        _ensure_column(conn, "alert_records", "eligibility_reason", "TEXT")
        _ensure_column(conn, "alert_records", "eligibility_updated_at_utc", "TEXT")
        _ensure_column(conn, "alert_records", "lifecycle_status", "TEXT NOT NULL DEFAULT 'active' CHECK(lifecycle_status IN ('active','retired'))")
        _ensure_column(conn, "alert_records", "retirement_reason", "TEXT")


def _safe_json_object(value):
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def _retirement_reason(node_type: str, value: str, field_paths: list[str]) -> str:
    parts = set()
    for field_path in field_paths:
        parts.update(_segments(field_path))
    if parts.intersection({"popular_threat_label", "threat_label", "malware_label", "detection", "detections", "family_labels", "threat_categories"}):
        return "Retired: detection/threat label is metadata, not a domain or infrastructure observable."
    if parts.intersection(FILENAME_FIELDS):
        return "Retired: filename was previously misclassified as a domain; filenames are metadata."
    if parts.intersection({"vendor", "vendors", "engine", "engines"}):
        return "Retired: vendor/engine name is metadata, not a domain observable."
    if node_type in {"ipv4-addr", "ipv6-addr"} and parts.intersection(RANGE_FIELDS):
        return "Retired: value came only from WHOIS/network allocation fields; ranges and boundaries are not host IPs."
    if node_type in {"ipv4-addr", "ipv6-addr"}:
        normalized, reason = validate_public_ip(value)
        if reason:
            return f"Retired: {reason}"
    if node_type == "domain-name":
        reason = domain_validation_reason(value)
        if reason:
            return f"Retired: {reason}"
    return "Retired: no longer yielded by field-aware passive evidence extraction."


def _retire_stale_artifacts(conn: sqlite3.Connection, active_node_ids: set[str]):
    retired_ids: dict[str, str] = {}
    anchor_ids = {
        row[0] for row in conn.execute("SELECT node_id FROM seed_anchors")
    } if _table_exists(conn, "seed_anchors") else set()

    for node_id, node_type, value, attributes_json, lifecycle in conn.execute(
        "SELECT node_id,node_type,value,attributes_json,lifecycle_status FROM infrastructure_nodes"
    ).fetchall():
        if node_id in active_node_ids or node_id in anchor_ids:
            continue
        try:
            attributes = json.loads(attributes_json or "{}")
        except (TypeError, json.JSONDecodeError):
            attributes = {}
        managed = (
            str(node_id).startswith("observable--")
            or attributes.get("extraction_method") in {"passive-evidence-v1", EXTRACTION_METHOD}
        )
        if not managed:
            continue
        paths = attributes.get("field_path") or attributes.get("field_paths") or []
        if isinstance(paths, str):
            paths = [paths]
        if not paths and _table_exists(conn, "entity_observations"):
            paths = [row[0] for row in conn.execute(
                "SELECT DISTINCT field_path FROM entity_observations WHERE node_id=?",
                (node_id,),
            )]
        reason = _retirement_reason(node_type, value, paths)
        attributes.update({
            "lifecycle_status": "retired",
            "exclusion_reason": reason,
            "field_path": sorted(set(str(path) for path in paths)),
        })
        if lifecycle != "retired":
            conn.execute(
                "UPDATE infrastructure_nodes SET lifecycle_status='retired',retirement_reason=?,attributes_json=? WHERE node_id=?",
                (reason, json.dumps(attributes, ensure_ascii=False, sort_keys=True), node_id),
            )
        elif not attributes_json or _safe_json_object(attributes_json) != attributes:
            conn.execute(
                "UPDATE infrastructure_nodes SET retirement_reason=?,attributes_json=? WHERE node_id=?",
                (reason, json.dumps(attributes, ensure_ascii=False, sort_keys=True), node_id),
            )
        retired_ids[node_id] = reason

    for node_id, reason in retired_ids.items():
        if _table_exists(conn, "infrastructure_edges"):
            conn.execute(
                "UPDATE infrastructure_edges SET lifecycle_status='retired',retirement_reason=? WHERE (source_node_id=? OR target_node_id=?) AND lifecycle_status<>'retired'",
                (f"Retired because endpoint node was retired: {reason}", node_id, node_id),
            )
        if _table_exists(conn, "alert_records"):
            conn.execute(
                "UPDATE alert_records SET lifecycle_status='retired',retirement_reason=?,eligibility='excluded',eligibility_reason=?,eligibility_updated_at_utc=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE node_id=? AND lifecycle_status<>'retired'",
                (reason, reason, node_id),
            )
    return len(retired_ids)


def extract_entities(db_path: Path) -> tuple[int, int, int, int]:
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    shared_entries = load_shared_infrastructure(SHARED_INFRA_FILE)
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        ensure_lifecycle_schema(conn)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_observations (
                evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
                node_id TEXT NOT NULL REFERENCES infrastructure_nodes(node_id),
                field_path TEXT NOT NULL,
                extraction_method TEXT NOT NULL,
                PRIMARY KEY(evidence_id,node_id,field_path,extraction_method)
            )
        """)
        conn.commit()

        endpoint_by_ip = {}
        for seed_id, node_id, attributes_json in conn.execute("""
            SELECT sa.seed_id,n.node_id,n.attributes_json
            FROM seed_anchors sa JOIN infrastructure_nodes n ON n.node_id=sa.node_id
            WHERE sa.seed_id IN ('S001','S002','S003','S004')
        """):
            attributes = json.loads(attributes_json or "{}")
            ip = attributes.get("ip_address")
            if ip:
                endpoint_by_ip.setdefault(ip, []).append(node_id)

        evidence_rows = conn.execute("""
            SELECT evidence_id,details_json FROM evidence_records
            WHERE seed_id IN ('S001','S002','S003','S004') ORDER BY evidence_id
        """).fetchall()

        new_nodes = 0
        new_observations = 0
        active_node_ids: set[str] = set()
        with conn:
            for evidence_id, details_json in evidence_rows:
                try:
                    payload = json.loads(details_json)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid evidence JSON in database: {evidence_id}") from exc
                if not isinstance(payload, (dict, list)):
                    continue

                entities = _validated_entities(payload, shared_entries)
                for (kind, value), item in sorted(entities.items()):
                    paths = sorted(item["field_paths"])
                    if kind in {"ipv4-addr", "ipv6-addr"}:
                        targets = endpoint_by_ip.get(value, [])
                    else:
                        targets = []

                    shared = item.get("shared")
                    attributes = {
                        "extraction_method": EXTRACTION_METHOD,
                        "field_path": paths,
                        "registrable_domain": item.get("registrable_domain"),
                        "is_shared_infrastructure": bool(shared),
                        "exclusion_reason": shared["reason"] if shared else None,
                        "shared_infrastructure": shared,
                        "lifecycle_status": "active",
                    }

                    if not targets:
                        node_id = "observable--" + hashlib.sha256(
                            f"{kind}|{value}".encode("utf-8")
                        ).hexdigest()
                        existing = conn.execute(
                            "SELECT node_id,attributes_json FROM infrastructure_nodes WHERE node_type=? AND normalized_value=?",
                            (kind, value),
                        ).fetchone()
                        if existing:
                            node_id = existing[0]
                            try:
                                old_attributes = json.loads(existing[1] or "{}")
                            except (TypeError, json.JSONDecodeError):
                                old_attributes = {}
                            old_attributes.update(attributes)
                            attributes = old_attributes
                            conn.execute(
                                "UPDATE infrastructure_nodes SET value=?,attributes_json=?,lifecycle_status='active',retirement_reason=NULL WHERE node_id=?",
                                (value, json.dumps(attributes, ensure_ascii=False, sort_keys=True), node_id),
                            )
                        else:
                            conn.execute(
                                "INSERT INTO infrastructure_nodes(node_id,node_type,value,normalized_value,attributes_json,created_at_utc,lifecycle_status,retirement_reason) VALUES (?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'),'active',NULL)",
                                (node_id, kind, value, value, json.dumps(attributes, ensure_ascii=False, sort_keys=True)),
                            )
                            new_nodes += 1
                        targets = [node_id]
                    else:
                        for node_id in targets:
                            row = conn.execute(
                                "SELECT attributes_json FROM infrastructure_nodes WHERE node_id=?",
                                (node_id,),
                            ).fetchone()
                            anchor_attributes = json.loads(row[0] or "{}") if row else {}
                            existing_paths = set(anchor_attributes.get("field_path", []))
                            anchor_attributes["field_path"] = sorted(existing_paths | set(paths))
                            conn.execute(
                                "UPDATE infrastructure_nodes SET attributes_json=?,lifecycle_status='active',retirement_reason=NULL WHERE node_id=?",
                                (json.dumps(anchor_attributes, ensure_ascii=False, sort_keys=True), node_id),
                            )

                    for node_id in targets:
                        active_node_ids.add(node_id)
                        cursor = conn.execute(
                            "INSERT OR IGNORE INTO entity_observations(evidence_id,node_id,field_path,extraction_method) VALUES(?,?,?,?)",
                            (evidence_id, node_id, next(iter(paths), "unknown"), EXTRACTION_METHOD),
                        )
                        new_observations += cursor.rowcount
                        for path in paths[1:]:
                            cursor = conn.execute(
                                "INSERT OR IGNORE INTO entity_observations(evidence_id,node_id,field_path,extraction_method) VALUES(?,?,?,?)",
                                (evidence_id, node_id, path, EXTRACTION_METHOD),
                            )
                            new_observations += cursor.rowcount

            retired_count = _retire_stale_artifacts(conn, active_node_ids)

        node_count = conn.execute("SELECT COUNT(*) FROM infrastructure_nodes").fetchone()[0]
        observation_count = conn.execute("SELECT COUNT(*) FROM entity_observations").fetchone()[0]

    logging.info("Field-aware extraction complete: new_nodes=%d new_observations=%d retired_nodes=%d", new_nodes, new_observations, retired_count)
    return new_nodes, new_observations, node_count, observation_count


def main() -> int:
    load_dotenv(ROOT / ".env", override=False)
    logging.basicConfig(
        filename=str(LOG_FILE), level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8", force=True,
    )
    try:
        nodes, observations, total_nodes, total_observations = extract_entities(DB_FILE)
        print(f"Database: {DB_FILE}")
        print(f"New observable nodes: {nodes}")
        print(f"New evidence observations: {observations}")
        print(f"Total infrastructure nodes: {total_nodes}")
        print(f"Total entity observations: {total_observations}")
        print("Extraction: field-aware; public IP/domain validation enabled.")
        print("Seed scope: S001-S004; raw evidence unchanged.")
        print("Retired nodes remain in the database with status and reason.")
        print("No relationships or actor attributions inferred.")
        return 0
    except Exception as exc:
        logging.exception("Entity extraction failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
