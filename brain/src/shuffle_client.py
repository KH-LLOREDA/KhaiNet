"""Shuffle SOAR integration client for KhaiNet Brain.

Sends incidents to Shuffle via webhook REST POST.
Maps severity_label to playbook. Destructive actions have auto_execute=false.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from src.models import Incident, label_to_playbook

log = structlog.get_logger()


class ShuffleClient:
    """Async client for Shuffle SOAR webhook."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.url = config.get("url", "http://localhost:3001")
        self.api_key = config.get("api_key", "")
        self.webhook_path = config.get(
            "webhook_path", "/api/v1/workflows/brain-incident/executions"
        )
        self.timeout = config.get("timeout_seconds", 15)
        self._http_client: httpx.AsyncClient | None = None

    def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._http_client = httpx.AsyncClient(timeout=self.timeout, headers=headers)
        return self._http_client

    def _build_webhook_url(self, incident: Incident) -> str:
        """Build the webhook URL with the appropriate playbook."""
        playbook = label_to_playbook(incident.severity_label)
        return f"{self.url}{self.webhook_path}?playbook={playbook}"

    def _build_payload(self, incident: Incident) -> dict[str, Any]:
        """Build the webhook payload from an incident."""
        return {
            "incident": incident.model_dump_json_safe(),
            "playbook": label_to_playbook(incident.severity_label),
            "severity": incident.severity,
            "severity_label": incident.severity_label
            if isinstance(incident.severity_label, str)
            else incident.severity_label.value,
            "auto_execute_actions": [
                a.model_dump(mode="json")
                for a in incident.recommended_actions
                if a.auto_execute
            ],
            "manual_review_actions": [
                a.model_dump(mode="json")
                for a in incident.recommended_actions
                if not a.auto_execute
            ],
        }

    async def send_incident(self, incident: Incident) -> dict[str, Any]:
        """Send an incident to Shuffle via webhook.

        Returns:
            Shuffle response dict (or error dict on failure).
        """
        url = self._build_webhook_url(incident)
        payload = self._build_payload(incident)

        try:
            client = self._get_http_client()
            response = await client.post(url, json=payload)
            response.raise_for_status()

            result = response.json() if response.content else {"status": "sent"}
            log.info(
                "shuffle_incident_sent",
                incident_id=incident.incident_id,
                severity_label=incident.severity_label,
                playbook=label_to_playbook(incident.severity_label),
                status_code=response.status_code,
            )
            return result
        except httpx.TimeoutException as e:
            log.error(
                "shuffle_timeout",
                incident_id=incident.incident_id,
                error=str(e),
            )
            return {"error": "timeout", "detail": str(e)}
        except httpx.HTTPStatusError as e:
            log.error(
                "shuffle_http_error",
                incident_id=incident.incident_id,
                status_code=e.response.status_code,
                error=str(e),
            )
            return {
                "error": "http_error",
                "status_code": e.response.status_code,
                "detail": str(e),
            }
        except (httpx.ConnectError, OSError) as e:
            log.error(
                "shuffle_connection_error",
                incident_id=incident.incident_id,
                error=str(e),
            )
            return {"error": "connection_error", "detail": str(e)}

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
