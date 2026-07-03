"""Parser for Zeek TSV log files.

Zeek generates logs in tab-separated values (TSV) format with header lines
starting with ``#``. The ``#fields`` line defines column names and ``#types``
defines column types. Empty values are represented by ``-``.

This parser reads conn.log, dns.log, http.log, and ssl.log files and converts
them to Pydantic models. IPs are pseudonymized with SHA-256+salt.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from src.models import ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL

log = structlog.get_logger()

# Salt for pseudonymization
_SALT = "khainet-salt"

# Mapping from Zeek log type to model class
LOG_TYPE_MAP: dict[str, type] = {
    "conn": ZeekConn,
    "dns": ZeekDNS,
    "http": ZeekHTTP,
    "ssl": ZeekSSL,
}

# Mapping from Zeek field names to model field names
FIELD_MAP = {
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
    "proto": "protocol",
    "qtype_name": "qtype",
    "ts": "timestamp",
}


def _pseudonymize_ip(ip: str) -> str:
    """Pseudonymize an IP address into a SHA-256 hash."""
    return hashlib.sha256(f"{_SALT}:{ip}".encode()).hexdigest()


def _parse_zeek_value(raw: str, zeek_type: str) -> Any:
    """Parse a single Zeek TSV value based on its type.

    Handles empty values (``-``) and type conversions.
    """
    if raw == "-" or raw == "":
        if zeek_type in ("count", "int", "port"):
            return 0
        if zeek_type == "interval":
            return 0.0
        if zeek_type == "bool":
            return False
        if zeek_type.startswith("vector"):
            return []
        return None

    if zeek_type in ("count", "int"):
        return int(raw)
    if zeek_type in ("port",):
        return int(raw)
    if zeek_type in ("interval", "double", "time"):
        return float(raw)
    if zeek_type == "bool":
        return raw in ("T", "true", "True", "1")
    if zeek_type.startswith("vector"):
        # Zeek vectors are comma-separated within the field
        if raw == "-" or raw == "":
            return []
        sep = ","
        items = raw.split(sep)
        inner_type = zeek_type[zeek_type.index("[") + 1 : zeek_type.index("]")]
        if inner_type in ("int", "count"):
            return [int(x) for x in items if x and x != "-"]
        return [x for x in items if x and x != "-"]
    return raw


def _parse_zeek_timestamp(raw: str) -> datetime:
    """Parse a Zeek epoch timestamp (seconds.microseconds) to datetime."""
    if raw == "-" or raw == "":
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    epoch = float(raw)
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _parse_header(lines: list[str]) -> tuple[list[str], list[str]] | None:
    """Parse the #fields and #types header lines from a Zeek log.

    Returns:
        Tuple of (field_names, type_names) or None if header not found.
    """
    fields: list[str] = []
    types: list[str] = []

    for line in lines:
        if line.startswith("#fields"):
            # Split on tab, skip the #fields prefix
            parts = line.split("\t")
            fields = parts[1:]
        elif line.startswith("#types"):
            parts = line.split("\t")
            types = parts[1:]

    if not fields:
        return None
    if not types:
        types = ["string"] * len(fields)
    return fields, types


def _build_model_kwargs(
    fields: list[str],
    types: list[str],
    values: list[str],
    pseudonymize: bool = True,
) -> dict[str, Any]:
    """Build a kwargs dict from Zeek fields/types/values for a Pydantic model."""
    kwargs: dict[str, Any] = {}

    for i, (field_name, zeek_type, raw_value) in enumerate(zip(fields, types, values)):
        # Map Zeek field name to model field name
        model_field = FIELD_MAP.get(field_name, field_name)

        # Handle timestamp specially
        if model_field == "timestamp":
            kwargs["timestamp"] = _parse_zeek_timestamp(raw_value)
            continue

        # Handle IP pseudonymization
        if model_field in ("src_ip", "dst_ip") and pseudonymize:
            if raw_value and raw_value != "-":
                kwargs[model_field] = _pseudonymize_ip(raw_value)
            else:
                kwargs[model_field] = _pseudonymize_ip("0.0.0.0")
            continue

        # Parse value based on type
        parsed = _parse_zeek_value(raw_value, zeek_type)
        kwargs[model_field] = parsed

    return kwargs


def parse_zeek_log_from_string(
    log_content: str,
    model_class: type,
    pseudonymize: bool = True,
) -> list:
    """Parse a Zeek log from a string.

    Args:
        log_content: The full TSV content of a Zeek log file.
        model_class: The Pydantic model class to parse into.
        pseudonymize: Whether to pseudonymize IPs.

    Returns:
        List of model instances.
    """
    lines = log_content.strip().split("\n")
    header = _parse_header(lines)
    if header is None:
        log.warning("no_header_found_in_log")
        return []

    fields, types = header
    results: list = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue

        values = line.split("\t")
        if len(values) < len(fields):
            # Pad with empty values
            values = values + ["-"] * (len(fields) - len(values))

        kwargs = _build_model_kwargs(fields, types, values, pseudonymize)
        try:
            obj = model_class(**kwargs)
            results.append(obj)
        except Exception as exc:
            log.warning("parse_error", error=str(exc), line=line[:100])

    log.debug("parsed_zeek_log", model=model_class.__name__, count=len(results))
    return results


def parse_zeek_log(
    path: str | Path,
    model_class: type,
    pseudonymize: bool = True,
) -> list:
    """Parse a Zeek log file and return a list of model instances.

    Args:
        path: Path to the Zeek .log file.
        model_class: The Pydantic model class to parse into.
        pseudonymize: Whether to pseudonymize IPs.

    Returns:
        List of model instances.
    """
    path = Path(path)
    if not path.exists():
        log.warning("log_file_not_found", path=str(path))
        return []

    content = path.read_text()
    return parse_zeek_log_from_string(content, model_class, pseudonymize)


def parse_conn_log(path: str | Path, pseudonymize: bool = True) -> list[ZeekConn]:
    """Parse a Zeek conn.log file."""
    return parse_zeek_log(path, ZeekConn, pseudonymize)


def parse_dns_log(path: str | Path, pseudonymize: bool = True) -> list[ZeekDNS]:
    """Parse a Zeek dns.log file."""
    return parse_zeek_log(path, ZeekDNS, pseudonymize)


def parse_http_log(path: str | Path, pseudonymize: bool = True) -> list[ZeekHTTP]:
    """Parse a Zeek http.log file."""
    return parse_zeek_log(path, ZeekHTTP, pseudonymize)


def parse_ssl_log(path: str | Path, pseudonymize: bool = True) -> list[ZeekSSL]:
    """Parse a Zeek ssl.log file."""
    return parse_zeek_log(path, ZeekSSL, pseudonymize)
