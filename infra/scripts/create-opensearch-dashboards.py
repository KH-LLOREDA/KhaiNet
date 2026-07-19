#!/usr/bin/env python3
"""
KhaiNet — OpenSearch Dashboards provisioning script.

Creates index patterns, visualizations, and dashboards via the
OpenSearch Dashboards Saved Objects API.

Usage:
    python3 create-opensearch-dashboards.py [--host HOST] [--port PORT]

Default: http://172.26.10.98:5601
"""

import json
import sys
import time
import urllib.request
import urllib.error
import argparse
from uuid import uuid4

# ─── Config ───────────────────────────────────────────────────────────────────

DEFAULT_HOST = "172.26.10.98"
DEFAULT_PORT = 5601

# Stable UUIDs for reproducible deployments
ID_INDEX_PATTERN_CONN = "khainet-conn-pattern"
ID_INDEX_PATTERN_DNS = "khainet-dns-pattern"
ID_INDEX_PATTERN_BRAIN = "khainet-brain-pattern"
ID_INDEX_PATTERN_ALL = "khainet-all-pattern"

# Dashboard IDs
ID_DASH_NETWORK_OVERVIEW = "khainet-dash-network-overview"
ID_DASH_THREAT_INCIDENTS = "khainet-dash-threat-incidents"
ID_DASH_DNS_ANALYTICS = "khainet-dash-dns-analytics"

# ─── HTTP helpers ─────────────────────────────────────────────────────────────


class OSDClient:
    def __init__(self, host, port):
        self.base = f"http://{host}:{port}"

    def _request(self, method, path, body=None, headers=None):
        url = f"{self.base}{path}"
        data = None
        hdrs = {"Content-Type": "application/json", "osd-xsrf": "true"}
        if headers:
            hdrs.update(headers)

        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode()
            elif isinstance(body, str):
                data = body.encode()

        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                err_body = json.loads(raw)
            except json.JSONDecodeError:
                err_body = raw
            return e.code, err_body
        except Exception as e:
            return 0, {"error": str(e)}

    def create_index_pattern(self, pattern_id, title, time_field="@timestamp"):
        """Create an index pattern via saved objects API."""
        body = {
            "attributes": {
                "title": title,
                "timeFieldName": time_field,
                "intervalName": None,
                "fields": [],
                "type": "index-pattern",
                "typeMeta": {},
            }
        }
        status, resp = self._request(
            "POST", f"/api/saved_objects/index-pattern/{pattern_id}", body
        )
        return status, resp

    def create_visualization(
        self, vis_id, title, vis_state, search_source, index_pattern_ref
    ):
        """Create a visualization saved object."""
        body = {
            "attributes": {
                "title": title,
                "visState": json.dumps(vis_state),
                "uiStateJSON": json.dumps({}),
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(search_source)
                },
            },
            "references": [
                {
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                    "id": index_pattern_ref,
                }
            ],
        }
        status, resp = self._request(
            "POST", f"/api/saved_objects/visualization/{vis_id}", body
        )
        return status, resp

    def create_dashboard(self, dash_id, title, panels, references):
        """Create a dashboard saved object."""
        body = {
            "attributes": {
                "title": title,
                "description": "KhaiNet NDR — auto-provisioned dashboard",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps(
                    {
                        "useMargins": True,
                        "syncColors": False,
                        "centerPanelContent": "",
                        "hidePanelTitles": False,
                    }
                ),
                "version": 1,
                "timeRestore": False,
            },
            "references": references,
        }
        status, resp = self._request(
            "POST", f"/api/saved_objects/dashboard/{dash_id}", body
        )
        return status, resp

    def find_saved_objects(self, stype):
        status, resp = self._request("GET", f"/api/saved_objects/_find?type={stype}")
        return status, resp

    def delete_saved_object(self, stype, sid):
        status, resp = self._request(
            "DELETE", f"/api/saved_objects/{stype}/{sid}?force=true"
        )
        return status, resp


# ─── Visualization builders ──────────────────────────────────────────────────


def build_tsvb_timeseries(
    title,
    index_pattern_id,
    field=None,
    metric="count",
    interval="auto",
    group_by=None,
    filters=None,
    color=None,
    axis_min=None,
    axis_max=None,
):
    """Build a TSVB time series visualization state."""
    series = {
        "id": str(uuid4())[:8],
        "color": color or "#6092C0",
        "split_mode": "everything",
        "metrics": [{"id": str(uuid4())[:8], "type": metric}],
        "separate_axis": 0,
        "axis_position": "right",
        "formatter": "number",
        "chart_type": "line",
        "line_width": 2,
        "point_size": 1,
        "fill": 0.5,
        "stacked": "none",
        "label": title,
    }
    if field and metric in ("sum", "avg", "max", "min", "cardinality"):
        series["metrics"][0]["field"] = field
    if group_by:
        series["split_mode"] = "terms"
        series["terms_field"] = group_by
        series["terms_size"] = 10
        series["terms_order"] = "desc"

    vis_state = {
        "title": title,
        "type": "metrics",
        "params": {
            "axis_formatter": "number",
            "axis_position": "left",
            "axis_scale": "normal",
            "background_color": ["#FFFFFF"],
            "bar_color": ["#6092C0"],
            "default_index_pattern": index_pattern_id,
            "filter": "",
            "id": str(uuid4())[:8],
            "index_pattern": index_pattern_id,
            "interval": interval,
            "isModifiable": True,
            "show_grid": 1,
            "show_legend": 1,
            "time_field": "@timestamp",
            "type": "timeseries",
            "series": [series],
        },
        "aggs": [],
        "data": {
            "series": [series],
            "timerange": {"min": "now-24h", "max": "now"},
        },
    }
    return vis_state


def build_vega_bar(title, index_pattern_id, agg_field, size=10, label_field=None):
    """Build a Vega-Lite bar chart visualization."""
    field_name = label_field or agg_field
    vega_spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "url": {
                "%context%": True,
                "%timefield%": "@timestamp",
                "index": index_pattern_id,
                "body": {
                    "size": 0,
                    "aggs": {
                        "agg1": {
                            "terms": {
                                "field": agg_field,
                                "size": size,
                                "order": {"_count": "desc"},
                            }
                        }
                    },
                },
            },
            "format": {"property": "aggregations.agg1.buckets"},
        },
        "mark": {"type": "bar", "tooltip": True},
        "encoding": {
            "x": {
                "field": "key",
                "type": "nominal",
                "axis": {"title": field_name, "labelAngle": -45},
            },
            "y": {
                "field": "doc_count",
                "type": "quantitative",
                "axis": {"title": "Count"},
            },
            "color": {"value": "#00B4D8"},
        },
    }
    vis_state = {
        "title": title,
        "type": "vega",
        "aggs": [],
        "params": {"spec": json.dumps(vega_spec)},
    }
    return vis_state


def build_pie(title, index_pattern_id, agg_field, size=10):
    """Build a pie/donut chart using Vega-Lite."""
    vega_spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "url": {
                "%context%": True,
                "%timefield%": "@timestamp",
                "index": index_pattern_id,
                "body": {
                    "size": 0,
                    "aggs": {
                        "agg1": {
                            "terms": {
                                "field": agg_field,
                                "size": size,
                                "order": {"_count": "desc"},
                            }
                        }
                    },
                },
            },
            "format": {"property": "aggregations.agg1.buckets"},
        },
        "mark": {"type": "arc", "tooltip": True, "innerRadius": 60},
        "encoding": {
            "theta": {"field": "doc_count", "type": "quantitative"},
            "color": {"field": "key", "type": "nominal", "legend": {"title": title}},
        },
    }
    vis_state = {
        "title": title,
        "type": "vega",
        "aggs": [],
        "params": {"spec": json.dumps(vega_spec)},
    }
    return vis_state


def build_metric_number(title, index_pattern_id, metric="count", field=None):
    """Build a TSVB metric (single number) visualization."""
    series = {
        "id": str(uuid4())[:8],
        "color": "#00B4D8",
        "split_mode": "everything",
        "metrics": [{"id": str(uuid4())[:8], "type": metric}],
        "separate_axis": 0,
        "axis_position": "right",
        "formatter": "number",
        "chart_type": "line",
        "line_width": 0,
        "point_size": 0,
        "fill": 0,
        "stacked": "none",
    }
    if field and metric in ("sum", "avg", "max", "min", "cardinality"):
        series["metrics"][0]["field"] = field

    vis_state = {
        "title": title,
        "type": "metrics",
        "params": {
            "axis_formatter": "number",
            "axis_position": "left",
            "axis_scale": "normal",
            "background_color": ["#FFFFFF"],
            "bar_color": ["#6092C0"],
            "default_index_pattern": index_pattern_id,
            "filter": "",
            "id": str(uuid4())[:8],
            "index_pattern": index_pattern_id,
            "interval": "auto",
            "isModifiable": True,
            "show_grid": 0,
            "show_legend": 0,
            "time_field": "@timestamp",
            "type": "metric",
            "series": [series],
        },
        "aggs": [],
        "data": {
            "series": [series],
            "timerange": {"min": "now-24h", "max": "now"},
        },
    }
    return vis_state


def build_data_table(
    title, index_pattern_id, columns, sort_field="@timestamp", sort_order="desc"
):
    """Build a data table visualization."""
    aggs = []
    for i, col in enumerate(columns):
        aggs.append(
            {
                "id": f"col-{i}",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": col,
                    "size": 50,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                    "customLabel": col,
                },
            }
        )

    vis_state = {
        "title": title,
        "type": "table",
        "params": {
            "perPage": 25,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "showToolbar": True,
            "percentageCol": "",
        },
        "aggs": aggs,
        "data": {},
    }
    return vis_state


def build_tag_cloud(title, index_pattern_id, field, size=15):
    """Build a tag cloud visualization."""
    vis_state = {
        "title": title,
        "type": "tagcloud",
        "params": {
            "scale": "linear",
            "orientation": "single",
            "minFontSize": 10,
            "maxFontSize": 36,
            "showLabel": True,
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": field,
                    "size": size,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                },
            }
        ],
        "data": {},
    }
    return vis_state


# ─── Main provisioning ───────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Provision KhaiNet OpenSearch Dashboards"
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete existing KhaiNet saved objects first",
    )
    args = parser.parse_args()

    client = OSDClient(args.host, args.port)

    # ─── Clean existing ──────────────────────────────────────────────────────
    if args.clean:
        print("🧹 Cleaning existing KhaiNet saved objects...")
        for stype in ["dashboard", "visualization", "index-pattern"]:
            status, resp = client.find_saved_objects(stype)
            if status == 200:
                for so in resp.get("saved_objects", []):
                    sid = so["id"]
                    if "khainet" in sid:
                        s, _ = client.delete_saved_object(stype, sid)
                        print(f"  Deleted {stype}/{sid}: {s}")
            time.sleep(0.2)

    # ─── 1. Index Patterns ───────────────────────────────────────────────────
    print("\n📋 Creating index patterns...")

    patterns = [
        (ID_INDEX_PATTERN_CONN, "zeek-conn*", "@timestamp"),
        (ID_INDEX_PATTERN_DNS, "zeek-dns*", "@timestamp"),
        (ID_INDEX_PATTERN_BRAIN, "brain-incidents*", "@timestamp"),
        (ID_INDEX_PATTERN_ALL, "zeek-*,brain-incidents*", "@timestamp"),
    ]

    for pid, title, time_field in patterns:
        status, resp = client.create_index_pattern(pid, title, time_field)
        if status in (200, 201):
            print(f"  ✅ {pid}: {title}")
        elif status == 409:
            print(f"  ⏭️  {pid}: already exists")
        else:
            print(f"  ❌ {pid}: {status} {resp}")
        time.sleep(0.3)

    # ─── 2. Visualizations ───────────────────────────────────────────────────
    print("\n📊 Creating visualizations...")

    visualizations = []
    vis_results = {}

    def make_vis(vis_id, title, vis_state, index_pattern_id):
        search_source = {
            "query": {"query": "", "language": "lucene"},
            "filter": [],
            "index": {"id": index_pattern_id, "type": "index-pattern", "name": title},
        }
        status, resp = client.create_visualization(
            vis_id, title, vis_state, search_source, index_pattern_id
        )
        vis_results[vis_id] = status
        if status in (200, 201):
            print(f"  ✅ {vis_id}: {title}")
        elif status == 409:
            print(f"  ⏭️  {vis_id}: already exists")
        else:
            print(f"  ❌ {vis_id}: {status} — {str(resp)[:200]}")
        time.sleep(0.2)

    # ─── Network Overview visualizations (zeek-conn) ─────────────────────────
    # 1. Events over time (line chart)
    make_vis(
        "khainet-vis-conn-events-time",
        "Network Events Over Time",
        build_tsvb_timeseries(
            "Network Events Over Time",
            ID_INDEX_PATTERN_CONN,
            metric="count",
            color="#00B4D8",
        ),
        ID_INDEX_PATTERN_CONN,
    )

    # 2. Events by protocol (pie)
    make_vis(
        "khainet-vis-conn-protocols",
        "Events by Protocol",
        build_pie("Events by Protocol", ID_INDEX_PATTERN_CONN, "protocol", size=10),
        ID_INDEX_PATTERN_CONN,
    )

    # 3. Top source IPs (bar)
    make_vis(
        "khainet-vis-conn-top-src-ips",
        "Top Source IPs",
        build_vega_bar("Top Source IPs", ID_INDEX_PATTERN_CONN, "src_ip", size=15),
        ID_INDEX_PATTERN_CONN,
    )

    # 4. Top destination IPs (bar)
    make_vis(
        "khainet-vis-conn-top-dst-ips",
        "Top Destination IPs",
        build_vega_bar("Top Destination IPs", ID_INDEX_PATTERN_CONN, "dst_ip", size=15),
        ID_INDEX_PATTERN_CONN,
    )

    # 5. Top destination ports (bar)
    make_vis(
        "khainet-vis-conn-top-dst-ports",
        "Top Destination Ports",
        build_vega_bar(
            "Top Destination Ports", ID_INDEX_PATTERN_CONN, "dst_port", size=15
        ),
        ID_INDEX_PATTERN_CONN,
    )

    # 6. Bytes transferred over time (area)
    make_vis(
        "khainet-vis-conn-bytes-time",
        "Bytes Transferred Over Time",
        build_tsvb_timeseries(
            "Bytes Transferred Over Time",
            ID_INDEX_PATTERN_CONN,
            field="orig_bytes",
            metric="sum",
            color="#06D6A0",
        ),
        ID_INDEX_PATTERN_CONN,
    )

    # 7. Connection states (pie)
    make_vis(
        "khainet-vis-conn-states",
        "Connection States",
        build_pie("Connection States", ID_INDEX_PATTERN_CONN, "conn_state", size=10),
        ID_INDEX_PATTERN_CONN,
    )

    # 8. Unique hosts (metric)
    make_vis(
        "khainet-vis-conn-unique-hosts",
        "Unique Hosts",
        build_metric_number(
            "Unique Hosts", ID_INDEX_PATTERN_CONN, metric="cardinality", field="src_ip"
        ),
        ID_INDEX_PATTERN_CONN,
    )

    # 9. Total events (metric)
    make_vis(
        "khainet-vis-conn-total-events",
        "Total Network Events",
        build_metric_number(
            "Total Network Events", ID_INDEX_PATTERN_CONN, metric="count"
        ),
        ID_INDEX_PATTERN_CONN,
    )

    # 10. Events by service (bar)
    make_vis(
        "khainet-vis-conn-services",
        "Events by Service",
        build_vega_bar("Events by Service", ID_INDEX_PATTERN_CONN, "service", size=10),
        ID_INDEX_PATTERN_CONN,
    )

    # ─── DNS Analytics visualizations (zeek-dns) ─────────────────────────────
    # 11. DNS queries over time
    make_vis(
        "khainet-vis-dns-queries-time",
        "DNS Queries Over Time",
        build_tsvb_timeseries(
            "DNS Queries Over Time",
            ID_INDEX_PATTERN_DNS,
            metric="count",
            color="#7209B7",
        ),
        ID_INDEX_PATTERN_DNS,
    )

    # 12. Top DNS queries (bar)
    make_vis(
        "khainet-vis-dns-top-queries",
        "Top DNS Queries",
        build_vega_bar("Top DNS Queries", ID_INDEX_PATTERN_DNS, "query", size=15),
        ID_INDEX_PATTERN_DNS,
    )

    # 13. DNS response codes (pie)
    make_vis(
        "khainet-vis-dns-rcodes",
        "DNS Response Codes",
        build_pie("DNS Response Codes", ID_INDEX_PATTERN_DNS, "rcode_name", size=10),
        ID_INDEX_PATTERN_DNS,
    )

    # 14. Top query types (bar)
    make_vis(
        "khainet-vis-dns-qtypes",
        "DNS Query Types",
        build_vega_bar("DNS Query Types", ID_INDEX_PATTERN_DNS, "qtype", size=10),
        ID_INDEX_PATTERN_DNS,
    )

    # 15. Top DNS source IPs (bar)
    make_vis(
        "khainet-vis-dns-top-src",
        "Top DNS Source IPs",
        build_vega_bar("Top DNS Source IPs", ID_INDEX_PATTERN_DNS, "src_ip", size=10),
        ID_INDEX_PATTERN_DNS,
    )

    # ─── Threat Incidents visualizations (brain-incidents) ───────────────────
    # 16. Incidents over time
    make_vis(
        "khainet-vis-brain-incidents-time",
        "Incidents Over Time",
        build_tsvb_timeseries(
            "Incidents Over Time",
            ID_INDEX_PATTERN_BRAIN,
            metric="count",
            color="#EF476F",
        ),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 17. Incidents by severity (bar)
    make_vis(
        "khainet-vis-brain-severity",
        "Incidents by Severity",
        build_vega_bar(
            "Incidents by Severity", ID_INDEX_PATTERN_BRAIN, "severity_label", size=10
        ),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 18. Incidents by status (pie)
    make_vis(
        "khainet-vis-brain-status",
        "Incidents by Status",
        build_pie("Incidents by Status", ID_INDEX_PATTERN_BRAIN, "status", size=10),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 19. Top incident source IPs (bar)
    make_vis(
        "khainet-vis-brain-top-src",
        "Top Threat Source IPs",
        build_vega_bar(
            "Top Threat Source IPs", ID_INDEX_PATTERN_BRAIN, "entities.src_ips", size=15
        ),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 20. Top incident tags (tag cloud)
    make_vis(
        "khainet-vis-brain-tags",
        "Incident Tags Cloud",
        build_tag_cloud("Incident Tags Cloud", ID_INDEX_PATTERN_BRAIN, "tags", size=20),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 21. Total incidents (metric)
    make_vis(
        "khainet-vis-brain-total",
        "Total Incidents",
        build_metric_number("Total Incidents", ID_INDEX_PATTERN_BRAIN, metric="count"),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 22. Avg confidence (metric)
    make_vis(
        "khainet-vis-brain-avg-confidence",
        "Avg Confidence",
        build_metric_number(
            "Avg Confidence", ID_INDEX_PATTERN_BRAIN, metric="avg", field="confidence"
        ),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 23. Incidents by ML model (bar) — from alerts.ml_model nested field
    make_vis(
        "khainet-vis-brain-ml-models",
        "Incidents by ML Model",
        build_vega_bar(
            "Incidents by ML Model", ID_INDEX_PATTERN_BRAIN, "alerts.ml_model", size=10
        ),
        ID_INDEX_PATTERN_BRAIN,
    )

    # 24. Incidents data table
    make_vis(
        "khainet-vis-brain-table",
        "Recent Incidents Table",
        build_data_table(
            "Recent Incidents Table",
            ID_INDEX_PATTERN_BRAIN,
            ["incident_id", "title", "severity_label", "status", "confidence"],
        ),
        ID_INDEX_PATTERN_BRAIN,
    )

    # ─── 3. Dashboards ───────────────────────────────────────────────────────
    print("\n🎯 Creating dashboards...")

    # ─── Dashboard 1: Network Overview ───────────────────────────────────────
    dash1_panels = [
        # Row 1: Metrics (y=0, h=100)
        {
            "id": "p1",
            "type": "visualization",
            "x": 0,
            "y": 0,
            "w": 6,
            "h": 8,
            "panelIndex": "p1",
        },
        {
            "id": "p2",
            "type": "visualization",
            "x": 6,
            "y": 0,
            "w": 6,
            "h": 8,
            "panelIndex": "p2",
        },
        {
            "id": "p3",
            "type": "visualization",
            "x": 12,
            "y": 0,
            "w": 6,
            "h": 8,
            "panelIndex": "p3",
        },
        {
            "id": "p4",
            "type": "visualization",
            "x": 18,
            "y": 0,
            "w": 6,
            "h": 8,
            "panelIndex": "p4",
        },
        # Row 2: Time series + pie (y=8, h=20)
        {
            "id": "p5",
            "type": "visualization",
            "x": 0,
            "y": 8,
            "w": 16,
            "h": 20,
            "panelIndex": "p5",
        },
        {
            "id": "p6",
            "type": "visualization",
            "x": 16,
            "y": 8,
            "w": 8,
            "h": 20,
            "panelIndex": "p6",
        },
        # Row 3: Bars (y=28, h=20)
        {
            "id": "p7",
            "type": "visualization",
            "x": 0,
            "y": 28,
            "w": 8,
            "h": 20,
            "panelIndex": "p7",
        },
        {
            "id": "p8",
            "type": "visualization",
            "x": 8,
            "y": 28,
            "w": 8,
            "h": 20,
            "panelIndex": "p8",
        },
        {
            "id": "p9",
            "type": "visualization",
            "x": 16,
            "y": 28,
            "w": 8,
            "h": 20,
            "panelIndex": "p9",
        },
        # Row 4: Bytes + states + services (y=48, h=20)
        {
            "id": "p10",
            "type": "visualization",
            "x": 0,
            "y": 48,
            "w": 12,
            "h": 20,
            "panelIndex": "p10",
        },
        {
            "id": "p11",
            "type": "visualization",
            "x": 12,
            "y": 48,
            "w": 6,
            "h": 20,
            "panelIndex": "p11",
        },
        {
            "id": "p12",
            "type": "visualization",
            "x": 18,
            "y": 48,
            "w": 6,
            "h": 20,
            "panelIndex": "p12",
        },
    ]
    dash1_refs = [
        {"name": f"panel_{p['panelIndex']}", "type": "visualization", "id": vid}
        for p, vid in zip(
            dash1_panels,
            [
                "khainet-vis-conn-total-events",
                "khainet-vis-conn-unique-hosts",
                "khainet-vis-conn-events-time",
                "khainet-vis-conn-bytes-time",
                "khainet-vis-conn-events-time",
                "khainet-vis-conn-protocols",
                "khainet-vis-conn-top-src-ips",
                "khainet-vis-conn-top-dst-ips",
                "khainet-vis-conn-top-dst-ports",
                "khainet-vis-conn-bytes-time",
                "khainet-vis-conn-states",
                "khainet-vis-conn-services",
            ],
        )
    ]
    # Fix: metrics and time series share vis IDs, need unique refs
    dash1_refs = [
        {
            "name": "panel_p1",
            "type": "visualization",
            "id": "khainet-vis-conn-total-events",
        },
        {
            "name": "panel_p2",
            "type": "visualization",
            "id": "khainet-vis-conn-unique-hosts",
        },
        {
            "name": "panel_p3",
            "type": "visualization",
            "id": "khainet-vis-conn-events-time",
        },
        {
            "name": "panel_p4",
            "type": "visualization",
            "id": "khainet-vis-conn-bytes-time",
        },
        {
            "name": "panel_p5",
            "type": "visualization",
            "id": "khainet-vis-conn-events-time",
        },
        {
            "name": "panel_p6",
            "type": "visualization",
            "id": "khainet-vis-conn-protocols",
        },
        {
            "name": "panel_p7",
            "type": "visualization",
            "id": "khainet-vis-conn-top-src-ips",
        },
        {
            "name": "panel_p8",
            "type": "visualization",
            "id": "khainet-vis-conn-top-dst-ips",
        },
        {
            "name": "panel_p9",
            "type": "visualization",
            "id": "khainet-vis-conn-top-dst-ports",
        },
        {
            "name": "panel_p10",
            "type": "visualization",
            "id": "khainet-vis-conn-bytes-time",
        },
        {"name": "panel_p11", "type": "visualization", "id": "khainet-vis-conn-states"},
        {
            "name": "panel_p12",
            "type": "visualization",
            "id": "khainet-vis-conn-services",
        },
    ]

    status, resp = client.create_dashboard(
        ID_DASH_NETWORK_OVERVIEW, "KhaiNet — Network Overview", dash1_panels, dash1_refs
    )
    if status in (200, 201):
        print(f"  ✅ {ID_DASH_NETWORK_OVERVIEW}: Network Overview")
    elif status == 409:
        print(f"  ⏭️  {ID_DASH_NETWORK_OVERVIEW}: already exists")
    else:
        print(f"  ❌ {ID_DASH_NETWORK_OVERVIEW}: {status} — {str(resp)[:300]}")

    # ─── Dashboard 2: Threat Incidents ───────────────────────────────────────
    dash2_panels = [
        # Row 1: Metrics (y=0, h=8)
        {
            "id": "p1",
            "type": "visualization",
            "x": 0,
            "y": 0,
            "w": 8,
            "h": 8,
            "panelIndex": "p1",
        },
        {
            "id": "p2",
            "type": "visualization",
            "x": 8,
            "y": 0,
            "w": 8,
            "h": 8,
            "panelIndex": "p2",
        },
        {
            "id": "p3",
            "type": "visualization",
            "x": 16,
            "y": 0,
            "w": 8,
            "h": 8,
            "panelIndex": "p3",
        },
        # Row 2: Time series + severity bar (y=8, h=20)
        {
            "id": "p4",
            "type": "visualization",
            "x": 0,
            "y": 8,
            "w": 16,
            "h": 20,
            "panelIndex": "p4",
        },
        {
            "id": "p5",
            "type": "visualization",
            "x": 16,
            "y": 8,
            "w": 8,
            "h": 20,
            "panelIndex": "p5",
        },
        # Row 3: Bars + pie (y=28, h=20)
        {
            "id": "p6",
            "type": "visualization",
            "x": 0,
            "y": 28,
            "w": 8,
            "h": 20,
            "panelIndex": "p6",
        },
        {
            "id": "p7",
            "type": "visualization",
            "x": 8,
            "y": 28,
            "w": 8,
            "h": 20,
            "panelIndex": "p7",
        },
        {
            "id": "p8",
            "type": "visualization",
            "x": 16,
            "y": 28,
            "w": 8,
            "h": 20,
            "panelIndex": "p8",
        },
        # Row 4: Tag cloud + table (y=48, h=24)
        {
            "id": "p9",
            "type": "visualization",
            "x": 0,
            "y": 48,
            "w": 12,
            "h": 24,
            "panelIndex": "p9",
        },
        {
            "id": "p10",
            "type": "visualization",
            "x": 12,
            "y": 48,
            "w": 12,
            "h": 24,
            "panelIndex": "p10",
        },
    ]
    dash2_refs = [
        {"name": "panel_p1", "type": "visualization", "id": "khainet-vis-brain-total"},
        {
            "name": "panel_p2",
            "type": "visualization",
            "id": "khainet-vis-brain-avg-confidence",
        },
        {
            "name": "panel_p3",
            "type": "visualization",
            "id": "khainet-vis-brain-severity",
        },
        {
            "name": "panel_p4",
            "type": "visualization",
            "id": "khainet-vis-brain-incidents-time",
        },
        {
            "name": "panel_p5",
            "type": "visualization",
            "id": "mkhainet-vis-brain-status",
        },
        {
            "name": "panel_p6",
            "type": "visualization",
            "id": "khainet-vis-brain-top-src",
        },
        {
            "name": "panel_p7",
            "type": "visualization",
            "id": "khainet-vis-brain-ml-models",
        },
        {"name": "panel_p8", "type": "visualization", "id": "khainet-vis-brain-tags"},
        {"name": "panel_p9", "type": "visualization", "id": "khainet-vis-brain-tags"},
        {"name": "panel_p10", "type": "visualization", "id": "khainet-vis-brain-table"},
    ]

    status, resp = client.create_dashboard(
        ID_DASH_THREAT_INCIDENTS, "KhaiNet — Threat Incidents", dash2_panels, dash2_refs
    )
    if status in (200, 201):
        print(f"  ✅ {ID_DASH_THREAT_INCIDENTS}: Threat Incidents")
    elif status == 409:
        print(f"  ⏭️  {ID_DASH_THREAT_INCIDENTS}: already exists")
    else:
        print(f"  ❌ {ID_DASH_THREAT_INCIDENTS}: {status} — {str(resp)[:300]}")

    # ─── Dashboard 3: DNS Analytics ──────────────────────────────────────────
    dash3_panels = [
        # Row 1: Time series (y=0, h=20)
        {
            "id": "p1",
            "type": "visualization",
            "x": 0,
            "y": 0,
            "w": 24,
            "h": 20,
            "panelIndex": "p1",
        },
        # Row 2: Bars + pie (y=20, h=20)
        {
            "id": "p2",
            "type": "visualization",
            "x": 0,
            "y": 20,
            "w": 8,
            "h": 20,
            "panelIndex": "p2",
        },
        {
            "id": "p3",
            "type": "visualization",
            "x": 8,
            "y": 20,
            "w": 8,
            "h": 20,
            "panelIndex": "p3",
        },
        {
            "id": "p4",
            "type": "visualization",
            "x": 16,
            "y": 20,
            "w": 8,
            "h": 20,
            "panelIndex": "p4",
        },
        # Row 3: Top DNS source IPs (y=40, h=20)
        {
            "id": "p5",
            "type": "visualization",
            "x": 0,
            "y": 40,
            "w": 24,
            "h": 20,
            "panelIndex": "p5",
        },
    ]
    dash3_refs = [
        {
            "name": "panel_p1",
            "type": "visualization",
            "id": "khainet-vis-dns-queries-time",
        },
        {
            "name": "panel_p2",
            "type": "visualization",
            "id": "khainet-vis-dns-top-queries",
        },
        {"name": "panel_p3", "type": "visualization", "id": "khainet-vis-dns-rcodes"},
        {"name": "panel_p4", "type": "visualization", "id": "khainet-vis-dns-qtypes"},
        {"name": "panel_p5", "type": "visualization", "id": "khainet-vis-dns-top-src"},
    ]

    status, resp = client.create_dashboard(
        ID_DASH_DNS_ANALYTICS, "KhaiNet — DNS Analytics", dash3_panels, dash3_refs
    )
    if status in (200, 201):
        print(f"  ✅ {ID_DASH_DNS_ANALYTICS}: DNS Analytics")
    elif status == 409:
        print(f"  ⏭️  {ID_DASH_DNS_ANALYTICS}: already exists")
    else:
        print(f"  ❌ {ID_DASH_DNS_ANALYTICS}: {status} — {str(resp)[:300]}")

    # ─── Summary ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("📊 KhaiNet OpenSearch Dashboards Provisioning Summary")
    print("=" * 60)

    # Count successes
    vis_ok = sum(1 for s in vis_results.values() if s in (200, 201))
    vis_skip = sum(1 for s in vis_results.values() if s == 409)
    vis_fail = sum(1 for s in vis_results.values() if s not in (200, 201, 409))

    print(f"  Index Patterns: 4")
    print(f"  Visualizations: {vis_ok} created, {vis_skip} skipped, {vis_fail} failed")
    print(f"  Dashboards: 3")
    print(f"\n  Access dashboards at: http://{args.host}:{args.port}")
    print(f"  → Dashboard menu → KhaiNet — Network Overview")
    print(f"  → Dashboard menu → KhaiNet — Threat Incidents")
    print(f"  → Dashboard menu → KhaiNet — DNS Analytics")


if __name__ == "__main__":
    main()
