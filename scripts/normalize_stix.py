from __future__ import annotations

import csv
import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from stix2 import (
    Bundle,
    DomainName,
    Identity,
    Indicator,
    IPv4Address,
    IPv6Address,
    URL,
)

ROOT = Path(__file__).resolve().parents[1]
INPUT_FILE = ROOT / "data" / "seeds" / "seeds.csv"
OUTPUT_FILE = ROOT / "exports" / "seeds_s001_s004_stix21.json"
LOG_FILE = ROOT / "logs" / "normalize_stix.log"

ALLOWED_SEED_IDS = ("S001", "S002", "S003", "S004")


class NormalizationError(ValueError):
    """Raised when seed data cannot be safely normalized."""


def _normalise_header(value: str) -> str:
    return value.strip().casefold().replace(" ", "_").replace("-", "_")


def _pick(row: dict, *names: str) -> str | None:
    normalized = {
        _normalise_header(str(key)): value
        for key, value in row.items()
        if key is not None
    }

    for name in names:
        value = normalized.get(_normalise_header(name))
        if value is not None and str(value).strip():
            return str(value).strip()

    return None


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.upper().endswith(" UTC"):
        text = text[:-4].strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise NormalizationError(
            f"Invalid first-seen timestamp: {value!r}"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _parse_port(value: str) -> int:
    if not value.isdigit():
        raise NormalizationError(f"Invalid port: {value!r}")

    port = int(value)
    if not 1 <= port <= 65535:
        raise NormalizationError(f"Port out of range: {port}")

    return port


def parse_ioc(raw: str, type_hint: str = "") -> tuple[str, str, int | None]:
    value = raw.strip()
    if not value:
        raise NormalizationError("IOC value is empty")

    # URL indicators retain their complete URL value.
    if "://" in value:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            raise NormalizationError(f"Invalid URL IOC: {value!r}")
        return "url", value, None

    # Bracketed IPv6 with an optional port.
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise NormalizationError(f"Invalid bracketed IPv6 IOC: {value!r}")

        host = value[1:closing]
        suffix = value[closing + 1:]
        port = None

        if suffix:
            if not suffix.startswith(":"):
                raise NormalizationError(f"Invalid endpoint: {value!r}")
            port = _parse_port(suffix[1:])

        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise NormalizationError(f"Invalid IP address: {host!r}") from exc

        if not isinstance(address, ipaddress.IPv6Address):
            raise NormalizationError("Bracket notation is supported for IPv6 only")

        return "ipv6-addr", str(address), port

    # Plain IPv4 or IPv6.
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv4Address):
            return "ipv4-addr", str(address), None
        return "ipv6-addr", str(address), None
    except ValueError:
        pass

    # IPv4:port or hostname:port.
    if value.count(":") == 1:
        host, possible_port = value.rsplit(":", 1)
        if possible_port.isdigit():
            port = _parse_port(possible_port)
            try:
                address = ipaddress.ip_address(host)
                if isinstance(address, ipaddress.IPv4Address):
                    return "ipv4-addr", str(address), port
                raise NormalizationError(
                    "Use bracket notation for IPv6 endpoints with a port"
                )
            except ValueError:
                pass

            try:
                domain = DomainName(value=host.lower())
                return "domain-name", domain.value, port
            except Exception as exc:
                raise NormalizationError(
                    f"Invalid hostname endpoint: {value!r}"
                ) from exc

    # Bare domain name.
    try:
        domain = DomainName(value=value.lower())
        return "domain-name", domain.value, None
    except Exception as exc:
        raise NormalizationError(
            f"Unsupported or invalid IOC {value!r} "
            f"(type hint: {type_hint or 'not provided'})"
        ) from exc


def _stix_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _make_pattern(kind: str, value: str, port: int | None) -> str:
    if port is not None:
        if kind not in ("ipv4-addr", "ipv6-addr", "domain-name"):
            raise NormalizationError(
                f"Port-based pattern is unsupported for {kind}"
            )
        return (
            "[network-traffic:dst_ref.value = "
            + _stix_quote(value)
            + f" AND network-traffic:dst_port = {port}]"
        )

    return f"[{kind}:value = {_stix_quote(value)}]"


def normalize_rows(rows: list[dict]) -> Bundle:
    selected = {}
    for row in rows:
        seed_id = _pick(row, "seed_id", "seed", "sample_id", "id")
        if not seed_id:
            raise NormalizationError("A CSV row has no seed ID")

        seed_id = seed_id.upper()
        if seed_id not in ALLOWED_SEED_IDS:
            continue

        if seed_id in selected:
            raise NormalizationError(f"Duplicate seed ID: {seed_id}")

        selected[seed_id] = row

    missing = [seed for seed in ALLOWED_SEED_IDS if seed not in selected]
    if missing:
        raise NormalizationError(
            "Missing required seeds: " + ", ".join(missing)
        )

    identity = Identity(
        name="Adversary Infrastructure Tracking and Clustering Project",
        identity_class="organization",
    )

    indicators = []

    for seed_id in ALLOWED_SEED_IDS:
        row = selected[seed_id]

        raw_ioc = _pick(
            row, "ioc_value", "ioc", "ioc_string",
            "indicator", "indicator_value", "value"
        )
        first_seen_text = _pick(
            row, "first_seen_utc", "first_seen",
            "first_seen_date", "date_added", "time_seen"
        )

        if not raw_ioc:
            raise NormalizationError(f"{seed_id}: IOC value is missing")
        if not first_seen_text:
            notes = _pick(row, "notes") or ""
            marker = "listing "
            position = notes.casefold().find(marker)

            if position >= 0:
                listing_date = notes[position + len(marker):position + len(marker) + 10]
                if len(listing_date) == 10:
                    first_seen_text = listing_date + "T00:00:00Z"

            if not first_seen_text:
                raise NormalizationError(f"{seed_id}: first-seen timestamp is missing")
        type_hint = _pick(row, "ioc_type", "indicator_type", "type") or ""
        source = _pick(row, "source", "source_name", "feed", "provider")
        threat = _pick(
            row, "threat_type", "malware", "malware_family", "family", "tags"
        )
        reference = _pick(row, "reference", "reference_url", "source_url")

        kind, value, port = parse_ioc(raw_ioc, type_hint)
        first_seen = parse_timestamp(first_seen_text)
        pattern = _make_pattern(kind, value, port)

        description = [f"Original IOC: {raw_ioc}"]
        if threat:
            description.append(f"Threat type: {threat}")
        if source:
            description.append(f"Source: {source}")

        external_reference = {
            "source_name": source or "local-seed-csv",
            "external_id": seed_id,
        }
        if reference and reference.lower().startswith(("http://", "https://")):
            external_reference["url"] = reference

        indicator = Indicator(
            name=f"{seed_id} - {kind}",
            description="\n".join(description),
            pattern=pattern,
            pattern_type="stix",
            pattern_version="2.1",
            valid_from=first_seen,
            created_by_ref=identity.id,
            labels=["malicious-activity"],
            external_references=[external_reference],
        )
        indicators.append(indicator)

    return Bundle(objects=[identity, *indicators])


def main() -> int:
    load_dotenv(ROOT / ".env", override=False)

    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )

    try:
        if not INPUT_FILE.is_file():
            raise FileNotFoundError(f"Seed CSV not found: {INPUT_FILE}")

        with INPUT_FILE.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))

        if not rows:
            raise NormalizationError("Seed CSV is empty")

        bundle = normalize_rows(rows)
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_FILE.write_text(
            bundle.serialize(pretty=True) + "\n",
            encoding="utf-8",
        )

        count = sum(1 for obj in bundle.objects if obj.type == "indicator")
        logging.info("Created STIX 2.1 bundle with %d indicators", count)

        print(f"STIX bundle created: {OUTPUT_FILE}")
        print(f"STIX version: 2.1")
        print(f"Indicators: {count}")
        print("Included seeds: S001, S002, S003, S004")
        return 0

    except Exception as exc:
        logging.exception("STIX normalization failed")
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
