"""Schema validation and hallucination detection for LLM output.

Validates:
1. Input alerts against the Pydantic ``Alert`` model.
2. LLM output against the ``LLMOutput`` model.
3. Hallucination detection: IPs/hosts in LLM output must exist in input or enrichment.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from src.models import Alert, LLMOutput


class SchemaValidationError(Exception):
    """Raised when a message or LLM output fails schema validation."""


# Pseudonymized IP hashes are hex strings (64 chars for SHA-256).
# We also detect real IPs for hallucination checking.
_REAL_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_HASH_RE = re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE)
# Hostname pattern: uppercase letters, digits, hyphens, at least 3 chars,
# optionally with domain suffix (e.g. SRV-DB-01, host.example.com)
_HOSTNAME_RE = re.compile(r"\b[A-Z][A-Z0-9-]{2,}(?:\.[A-Za-z0-9-]+)*\b")
# Alert ID pattern: UUID-like strings
_ALERT_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def validate_alert(data: dict[str, Any]) -> Alert:
    """Validate a raw alert dict against the Alert model.

    Raises:
        SchemaValidationError: If validation fails.
    """
    try:
        return Alert(**data)
    except ValidationError as e:
        raise SchemaValidationError(f"Alert validation failed: {e}") from e


def validate_llm_output(data: dict[str, Any]) -> LLMOutput:
    """Validate LLM output dict against the LLMOutput model.

    Raises:
        SchemaValidationError: If validation fails.
    """
    try:
        return LLMOutput(**data)
    except ValidationError as e:
        raise SchemaValidationError(f"LLM output validation failed: {e}") from e


def extract_ips(text: str) -> set[str]:
    """Extract all IP-like strings (real IPs or pseudonymized hashes) from *text*."""
    found: set[str] = set()
    found.update(_REAL_IP_RE.findall(text))
    found.update(_HEX_HASH_RE.findall(text))
    return found


def extract_hostnames(text: str) -> set[str]:
    """Extract hostname-like strings from *text*.

    Matches uppercase hostnames (e.g. ``SRV-DB-01``, ``WEB-SERVER-02``)
    and domain names (e.g. ``host.example.com``).
    """
    return set(_HOSTNAME_RE.findall(text))


def extract_alert_ids(text: str) -> set[str]:
    """Extract UUID-like alert IDs from *text*."""
    return set(_ALERT_ID_RE.findall(text))


def _collect_input_ips(
    alert_group: dict[str, Any], enrichment: dict[str, Any]
) -> set[str]:
    """Collect all valid IPs/hashes from the input alert group and enrichment."""
    ips: set[str] = set()
    for alert in alert_group.get("alerts", []):
        if alert.get("src_ip"):
            ips.add(alert["src_ip"])
        if alert.get("dst_ip"):
            ips.add(alert["dst_ip"])
    # Enrichment may contain hostnames or IPs in asset_info / geoip
    entities = alert_group.get("entities", {})
    for key in ("src_ips", "dst_ips"):
        for ip in entities.get(key, []):
            ips.add(ip)
    return ips


def _collect_input_hostnames(
    alert_group: dict[str, Any], enrichment: dict[str, Any]
) -> set[str]:
    """Collect all hostnames from the input alert group and enrichment."""
    hostnames: set[str] = set()
    for alert in alert_group.get("alerts", []):
        raw_event = alert.get("raw_event", {})
        if raw_event.get("hostname"):
            hostnames.add(raw_event["hostname"])
    # From enrichment asset_info
    asset = enrichment.get("asset_info", {})
    if asset.get("hostname"):
        hostnames.add(asset["hostname"])
    # From entities
    entities = alert_group.get("entities", {})
    for key in ("src_hosts", "dst_hosts"):
        for host in entities.get(key, []):
            hostnames.add(host)
    return hostnames


def _collect_input_alert_ids(alert_group: dict[str, Any]) -> set[str]:
    """Collect all alert IDs from the input alert group."""
    ids: set[str] = set()
    for alert in alert_group.get("alerts", []):
        if alert.get("alert_id"):
            ids.add(alert["alert_id"])
    return ids


def detect_hallucinations(
    llm_output: dict[str, Any],
    input_group: dict[str, Any],
    enrichment: dict[str, Any] | None = None,
) -> list[str]:
    """Detect hallucinated IPs, hostnames, and alert references in LLM output.

    Checks that all IPs, hostnames, and alert IDs mentioned in the LLM's text
    fields exist in the input alert group or enrichment data (spec §8.4).

    Returns:
        List of hallucination error messages (empty if clean).
    """
    enrichment = enrichment or {}
    errors: list[str] = []

    input_ips = _collect_input_ips(input_group, enrichment)
    input_hostnames = _collect_input_hostnames(input_group, enrichment)
    input_alert_ids = _collect_input_alert_ids(input_group)

    # Collect all text from LLM output
    text_fields = [
        llm_output.get("title", ""),
        llm_output.get("description", ""),
        llm_output.get("explanation", ""),
        llm_output.get("correlation_reason", ""),
        llm_output.get("false_positive_assessment", ""),
    ]
    for action in llm_output.get("recommended_actions", []):
        if isinstance(action, dict):
            text_fields.append(action.get("justification", ""))
            text_fields.append(action.get("target", ""))

    all_text = " ".join(text_fields)

    # --- IP hallucination check ---
    output_ips = extract_ips(all_text)
    output_ips = {ip for ip in output_ips if len(ip) >= 7}
    hallucinated_ips = output_ips - input_ips
    if hallucinated_ips:
        errors.append(f"LLM invented IPs not present in input: {hallucinated_ips}")

    # --- Hostname hallucination check ---
    output_hostnames = extract_hostnames(all_text)
    # Filter out common words that match the hostname pattern but aren't hostnames
    # (e.g. single uppercase words in Spanish text)
    output_hostnames = {h for h in output_hostnames if len(h) >= 5 and "-" in h}
    hallucinated_hostnames = output_hostnames - input_hostnames
    if hallucinated_hostnames:
        errors.append(
            f"LLM invented hostnames not present in input: {hallucinated_hostnames}"
        )

    # --- Alert ID hallucination check ---
    output_alert_ids = extract_alert_ids(all_text)
    hallucinated_alert_ids = output_alert_ids - input_alert_ids
    if hallucinated_alert_ids:
        errors.append(
            f"LLM referenced alert IDs not present in input: {hallucinated_alert_ids}"
        )

    return errors


def validate_and_check_hallucinations(
    llm_output: dict[str, Any],
    input_group: dict[str, Any],
    enrichment: dict[str, Any] | None = None,
) -> LLMOutput:
    """Full validation: schema + hallucination detection.

    Raises:
        SchemaValidationError: If schema validation or hallucination check fails.
    """
    validated = validate_llm_output(llm_output)
    hallucination_errors = detect_hallucinations(llm_output, input_group, enrichment)
    if hallucination_errors:
        raise SchemaValidationError("; ".join(hallucination_errors))
    return validated
