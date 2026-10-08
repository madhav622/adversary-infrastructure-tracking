import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from normalize_stix import (
    ALLOWED_SEED_IDS,
    NormalizationError,
    normalize_rows,
    parse_ioc,
    parse_timestamp,
)


def test_ipv4_endpoint():
    assert parse_ioc("1.14.73.118:34091") == (
        "ipv4-addr", "1.14.73.118", 34091
    )


def test_bare_ipv6():
    assert parse_ioc("2001:db8::1") == (
        "ipv6-addr", "2001:db8::1", None
    )


def test_bracketed_ipv6_endpoint():
    assert parse_ioc("[2001:db8::1]:31337") == (
        "ipv6-addr", "2001:db8::1", 31337
    )


def test_domain_and_url():
    assert parse_ioc("example.com") == (
        "domain-name", "example.com", None
    )
    assert parse_ioc("https://example.com/path")[0] == "url"


def test_naive_timestamp_is_utc():
    result = parse_timestamp("2026-09-30 10:00:00")
    assert result.utcoffset().total_seconds() == 0


def test_normalizes_only_s001_to_s004():
    rows = [
        {
            "seed_id": seed_id,
            "ioc_type": "ip:port",
            "ioc": value,
            "first_seen_utc": "2026-09-30T00:00:00Z",
            "source": "ThreatFox",
        }
        for seed_id, value in [
            ("S001", "1.14.73.118:34091"),
            ("S002", "101.42.108.164:31337"),
            ("S003", "103.250.172.230:31337"),
            ("S004", "103.253.42.61:31337"),
            ("S005", "192.0.2.1:12345"),
        ]
    ]

    bundle = normalize_rows(rows)
    indicators = [obj for obj in bundle.objects if obj.type == "indicator"]

    assert len(indicators) == 4
    assert {obj.name.split(" - ")[0] for obj in indicators} == set(
        ALLOWED_SEED_IDS
    )
    assert any(
        "dst_port = 34091" in obj.pattern for obj in indicators
    )


def test_missing_seed_is_rejected():
    rows = [
        {
            "seed_id": seed_id,
            "ioc": value,
            "first_seen": "2026-09-30T00:00:00Z",
        }
        for seed_id, value in [
            ("S001", "1.14.73.118"),
            ("S002", "101.42.108.164"),
            ("S003", "103.250.172.230"),
        ]
    ]

    with pytest.raises(NormalizationError, match="Missing required seeds"):
        normalize_rows(rows)
