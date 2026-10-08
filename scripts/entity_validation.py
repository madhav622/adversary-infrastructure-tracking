from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PSL_FILE = ROOT / "config" / "public_suffix_list.dat"
SHARED_INFRA_FILE = ROOT / "config" / "shared_infrastructure.json"

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
PSEUDO_TLDS = {
    "test", "example", "invalid", "localhost", "local", "onion",
    "txt", "sliver", "exe", "dll", "bat", "cmd", "ps1", "psm1",
    "py", "pyc", "pyo", "sh", "bash", "bin", "dat", "log", "csv",
    "json", "xml", "yaml", "yml", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "zip", "7z", "rar", "gz", "tar", "bz2",
    "jpg", "jpeg", "png", "gif", "svg", "ico", "mp3", "mp4", "avi",
    "mov", "html", "htm", "css", "js", "jsx", "ts", "tsx", "php",
    "asp", "aspx", "jsp", "war", "jar", "apk", "elf", "so", "tmp",
    "temp", "bak", "old", "new", "backup",
}


def _load_rules(path: Path):
    if not Path(path).is_file():
        raise FileNotFoundError(f"Public Suffix List not found: {path}")
    exact: set[str] = set()
    wildcard: set[str] = set()
    exceptions: set[str] = set()
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            rule = line.strip()
            if not rule or rule.startswith("//") or rule.startswith("#"):
                continue
            if rule.startswith("!"):
                exceptions.add(rule[1:].casefold())
            elif rule.startswith("*."):
                wildcard.add(rule[2:].casefold())
            else:
                exact.add(rule.casefold())
    if not exact:
        raise ValueError(f"Public Suffix List has no rules: {path}")
    return exact, wildcard, exceptions


@lru_cache(maxsize=4)
def _cached_rules(path_text: str, mtime_ns: int, size: int):
    return _load_rules(Path(path_text))


def _rules(path: Path):
    stat = Path(path).stat()
    return _cached_rules(str(Path(path).resolve()), stat.st_mtime_ns, stat.st_size)


def normalize_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate or any(ch in candidate for ch in " /\\:@?#\t\r\n"):
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii").casefold()
    except (UnicodeError, ValueError):
        return None
    if len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        return None
    if labels[-1] in PSEUDO_TLDS:
        return None
    return candidate


def public_suffix_length(domain: str, psl_file: Path = PSL_FILE) -> int | None:
    """Return matching PSL rule length; None means suffix is unrecognized."""
    labels = domain.split(".")
    exact, wildcard, exceptions = _rules(Path(psl_file))
    best = 0

    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in exceptions:
            return len(candidate.split(".")) - 1
        if candidate in exact:
            best = max(best, len(candidate.split(".")))
        if index + 1 < len(labels):
            suffix = ".".join(labels[index + 1:])
            if suffix in wildcard:
                best = max(best, len(suffix.split(".")) + 1)
    return best or None


def registrable_domain(value: object, psl_file: Path = PSL_FILE) -> str | None:
    normalized = normalize_domain(value)
    if not normalized:
        return None
    labels = normalized.split(".")
    suffix_len = public_suffix_length(normalized, psl_file)
    if suffix_len is None or len(labels) <= suffix_len:
        return None
    return ".".join(labels[-(suffix_len + 1):])


def load_shared_infrastructure(path: Path = SHARED_INFRA_FILE) -> list[dict]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Shared infrastructure list not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if data.get("schema_version") != 1 or not isinstance(data.get("entries"), list):
        raise ValueError("Unsupported shared infrastructure list schema")
    entries = []
    for item in data["entries"]:
        if not isinstance(item, dict):
            raise ValueError("Shared infrastructure entries must be objects")
        cidr = item.get("cidr")
        source = item.get("source")
        reason = item.get("reason")
        added_date = item.get("added_date")
        if not all(isinstance(v, str) and v.strip() for v in (cidr, source, reason, added_date)):
            raise ValueError(f"Incomplete shared infrastructure entry: {item!r}")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid shared infrastructure CIDR: {cidr}") from exc
        entries.append({**item, "_network": network})
    return entries


def shared_infrastructure_match(value: object, entries: list[dict] | None = None):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    for item in entries if entries is not None else load_shared_infrastructure():
        network = item.get("_network")
        if network is None:
            network = ipaddress.ip_network(item["cidr"], strict=False)
        if address.version == network.version and address in network:
            return {
                "provider": item.get("provider", "Shared infrastructure"),
                "cidr": item["cidr"],
                "source": item["source"],
                "reason": item["reason"],
                "added_date": item["added_date"],
            }
    return None


def validate_public_ip(value: object):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, "Invalid IP address."
    if not address.is_global:
        return None, "Non-public, private, reserved, or otherwise non-global IP address."
    return address.compressed, None


def domain_validation_reason(value: object, psl_file: Path = PSL_FILE) -> str | None:
    normalized = normalize_domain(value)
    if normalized is None:
        raw = str(value).strip() if value is not None else ""
        suffix = raw.rstrip(".").rsplit(".", 1)[-1].casefold() if "." in raw else ""
        if suffix in PSEUDO_TLDS:
            return f"Rejected pseudo-TLD/file extension: .{suffix}."
        return "Invalid hostname syntax or missing registrable public suffix."
    if registrable_domain(normalized, psl_file) is None:
        return "Domain has no registrable domain under the bundled Public Suffix List."
    return None
