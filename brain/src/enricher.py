"""Parallel enrichment engine for KhaiNet Brain.

Enriches alert groups with 4 independent data sources in parallel:
- **Asset inventory** (OpenSearch) — hostname, type, criticality, OS, services
- **GeoIP** (MaxMind GeoLite2 local DB) — country, city, ASN, organization
- **Threat intel** (MISP via PyMISP) — IOCs, tags, reputation
- **Historical** (ClickHouse) — baseline, first-seen, deviation

All sources are fetched concurrently with ``asyncio.gather(return_exceptions=True)``.
If a source fails, enrichment continues with the rest and ``partial`` is set.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from src.models import (
    AlertGroup,
    AssetInfo,
    EnrichmentData,
    GeoIpInfo,
    HistoricalContext,
    ThreatIntelInfo,
)

log = structlog.get_logger()


class Enricher:
    """Parallel enrichment engine.

    Each source lookup is an async method that can be individually mocked.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.timeout = config.get("timeout_seconds", 10)
        # Clients are initialized lazily or injected for testing
        self._opensearch_client: Any = None
        self._geoip_reader: Any = None
        self._misp_client: Any = None
        self._clickhouse_client: Any = None

    # ------------------------------------------------------------------
    # Individual enrichment sources
    # ------------------------------------------------------------------

    async def asset_lookup(self, src_ips: list[str]) -> AssetInfo:
        """Look up asset information from OpenSearch or internal DB."""
        try:
            if self._opensearch_client is None:
                return AssetInfo()

            # Query OpenSearch for asset info by IP hash
            # In production, this would be a real query
            query = {
                "size": 1,
                "query": {
                    "bool": {"should": [{"term": {"ip_hash": ip}} for ip in src_ips]}
                },
            }

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self._opensearch_client.search(body=query),
            )

            hits = response.get("hits", {}).get("hits", [])
            if hits:
                source = hits[0]["_source"]
                return AssetInfo(
                    hostname=source.get("hostname"),
                    type=source.get("type"),
                    criticality=source.get("criticality", 2),
                    os=source.get("os"),
                    services=source.get("services", []),
                    owner=source.get("owner"),
                )
            return AssetInfo()
        except (asyncio.TimeoutError, OSError, RuntimeError, ValueError) as e:
            log.warning("asset_lookup_failed", error=str(e), src_ips=src_ips)
            raise

    async def geoip_lookup(self, dst_ips: list[str]) -> GeoIpInfo:
        """Look up GeoIP information from local MaxMind database."""
        try:
            if self._geoip_reader is None:
                return GeoIpInfo()

            # Pseudonymized IPs are hashes, not real IPs.
            # In production, the pipeline would de-pseudonymize or use a mapping.
            # For now, return empty if IPs are hashes.
            info = GeoIpInfo()
            for ip in dst_ips:
                # Only look up real IPs (not hashes)
                if len(ip) > 40:  # SHA-256 hash
                    continue
                try:
                    loop = asyncio.get_running_loop()
                    response = await loop.run_in_executor(
                        None, self._geoip_reader.city, ip
                    )
                    info.dst_country = response.country.iso_code
                    info.dst_city = response.city.name
                    info.dst_asn = str(response.autonomous_system_number)
                    info.dst_asn_org = response.autonomous_system_organization
                    break  # Use first match
                except (ValueError, OSError, RuntimeError):
                    continue
            return info
        except (asyncio.TimeoutError, OSError, RuntimeError) as e:
            log.warning("geoip_lookup_failed", error=str(e), dst_ips=dst_ips)
            raise

    async def threat_intel_lookup(
        self, src_ips: list[str], dst_ips: list[str]
    ) -> ThreatIntelInfo:
        """Look up threat intelligence from MISP."""
        try:
            if self._misp_client is None:
                return ThreatIntelInfo()

            info = ThreatIntelInfo()
            all_ips = src_ips + dst_ips

            for ip in all_ips:
                # Search MISP for IP attributes
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda ip=ip: self._misp_client.search(
                        controllers="attributes",
                        type_attribute="ip-dst",
                        value=ip,
                        pythonify=True,
                    ),
                )
                if result:
                    info.dst_ip_malicious = True
                    tags_set: set[str] = set()
                    for attr in result:
                        for tag in getattr(attr, "tags", []) or []:
                            tag_name = getattr(tag, "name", str(tag))
                            tags_set.add(tag_name)
                    info.dst_ip_tags = list(tags_set)
                    break

            return info
        except (asyncio.TimeoutError, OSError, RuntimeError, ValueError) as e:
            log.warning("threat_intel_lookup_failed", error=str(e))
            raise

    async def historical_lookup(
        self, src_ips: list[str], dst_ips: list[str]
    ) -> HistoricalContext:
        """Look up historical baseline from ClickHouse."""
        try:
            if self._clickhouse_client is None:
                return HistoricalContext()

            # Query ClickHouse for baseline statistics
            # In production, this would query the network baseline table
            query = """
                SELECT
                    dst_ip,
                    min(timestamp) as first_seen,
                    quantile(0.99)(bytes_out) as baseline_p99,
                    sum(bytes_out) as total_bytes_out
                FROM network_baseline
                WHERE src_ip IN %(src_ips)s
                GROUP BY dst_ip
                ORDER BY total_bytes_out DESC
                LIMIT 1
            """

            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._clickhouse_client.query(
                    query, parameters={"src_ips": src_ips}
                ),
            )

            rows = result.result_rows
            if rows:
                row = rows[0]
                baseline_p99 = float(row[2]) if row[2] else 0
                actual = float(row[3]) if row[3] else 0
                deviation = actual / baseline_p99 if baseline_p99 > 0 else 0.0
                return HistoricalContext(
                    first_seen_dst=str(row[1]) if row[1] else None,
                    baseline_bytes_out_p99=baseline_p99,
                    actual_bytes_out=actual,
                    deviation_factor=deviation,
                )
            return HistoricalContext()
        except (asyncio.TimeoutError, OSError, RuntimeError, ValueError) as e:
            log.warning("historical_lookup_failed", error=str(e))
            raise

    # ------------------------------------------------------------------
    # Parallel enrichment
    # ------------------------------------------------------------------

    async def enrich(self, alert_group: AlertGroup) -> EnrichmentData:
        """Enrich an alert group with all sources in parallel.

        Uses ``asyncio.gather(return_exceptions=True)`` so that if one source
        fails, the others still succeed. Sets ``partial=True`` if any failed.
        """
        src_ips = alert_group.get_src_ips()
        dst_ips = alert_group.get_dst_ips()

        results = await asyncio.gather(
            self.asset_lookup(src_ips),
            self.geoip_lookup(dst_ips),
            self.threat_intel_lookup(src_ips, dst_ips),
            self.historical_lookup(src_ips, dst_ips),
            return_exceptions=True,
        )

        asset_info, geoip, threat_intel, historical = results

        failed_sources: list[str] = []
        if isinstance(asset_info, Exception):
            asset_info = AssetInfo()
            failed_sources.append("asset")
        if isinstance(geoip, Exception):
            geoip = GeoIpInfo()
            failed_sources.append("geoip")
        if isinstance(threat_intel, Exception):
            threat_intel = ThreatIntelInfo()
            failed_sources.append("threat_intel")
        if isinstance(historical, Exception):
            historical = HistoricalContext()
            failed_sources.append("historical")

        enrichment = EnrichmentData(
            asset_info=asset_info if isinstance(asset_info, AssetInfo) else AssetInfo(),
            geoip=geoip if isinstance(geoip, GeoIpInfo) else GeoIpInfo(),
            threat_intel=threat_intel
            if isinstance(threat_intel, ThreatIntelInfo)
            else ThreatIntelInfo(),
            historical_context=historical
            if isinstance(historical, HistoricalContext)
            else HistoricalContext(),
            partial=len(failed_sources) > 0,
            failed_sources=failed_sources,
        )

        if failed_sources:
            log.info(
                "enrichment_partial",
                failed_sources=failed_sources,
                entity=alert_group.entity,
            )

        return enrichment

    # ------------------------------------------------------------------
    # Client setters (for dependency injection / testing)
    # ------------------------------------------------------------------

    def set_opensearch_client(self, client: Any) -> None:
        self._opensearch_client = client

    def set_geoip_reader(self, reader: Any) -> None:
        self._geoip_reader = reader

    def set_misp_client(self, client: Any) -> None:
        self._misp_client = client

    def set_clickhouse_client(self, client: Any) -> None:
        self._clickhouse_client = client
