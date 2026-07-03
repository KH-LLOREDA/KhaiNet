"""Synthetic data generator for mock mode and testing.

Generates realistic Zeek logs (conn, dns, http, ssl) without requiring real
infrastructure. All IPs are pseudonymized SHA-256 hashes. Anomalies are
injected at a configurable ratio for model validation.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

import structlog

from src.models import ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL

log = structlog.get_logger()

# Salt for pseudonymization (matches config)
_SALT = "khainet-salt"

# Common services and ports
COMMON_PORTS = {
    80: "http",
    443: "ssl",
    22: "ssh",
    53: "dns",
    25: "smtp",
    445: "smb",
    3389: "rdp",
    8080: "http",
}

# Common HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD"]

# Common user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.88.1",
    "Python-urllib/3.11",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101",
]

# Common DNS query domains
DNS_DOMAINS = [
    "example.com",
    "google.com",
    "github.com",
    "cloudflare.com",
    "amazonaws.com",
    "microsoft.com",
    "internal.corp.local",
    "api.service.io",
]

# Common HTTP hosts
HTTP_HOSTS = [
    "api.example.com",
    "www.google.com",
    "github.com",
    "registry.internal.corp",
    "cdn.cloudflare.com",
]

# SSL server names
SSL_SERVER_NAMES = [
    "www.google.com",
    "api.example.com",
    "github.com",
    "internal.corp.local",
    "cdn.cloudflare.com",
]

# SSL ciphers and versions
SSL_VERSIONS = ["TLSv1.2", "TLSv1.3"]
SSL_CIPHERS = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
]


def _pseudonymize_ip(seed: str) -> str:
    """Pseudonymize an IP-like string into a SHA-256 hash (GDPR compliance)."""
    return hashlib.sha256(f"{_SALT}:{seed}".encode()).hexdigest()


def _random_ip(rng: random.Random, prefix: str = "host") -> str:
    """Generate a random pseudonymized IP hash."""
    return _pseudonymize_ip(f"{prefix}-{rng.randint(0, 10_000_000)}")


def _make_uid(rng: random.Random) -> str:
    """Generate a Zeek-style UID (hex string)."""
    return "".join(rng.choice("0123456789abcdef") for _ in range(16))


# ---------------------------------------------------------------------------
# Zeek TSV log string generation
# ---------------------------------------------------------------------------

# Zeek log type → field names
ZEEK_FIELDS = {
    "conn": [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "orig_pkts",
        "resp_pkts",
    ],
    "dns": [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "query",
        "qclass",
        "qtype_name",
        "rcode",
        "rcode_name",
        "answers",
        "ttl",
    ],
    "http": [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "method",
        "host",
        "uri",
        "user_agent",
        "status_code",
        "request_body_len",
        "response_body_len",
    ],
    "ssl": [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "version",
        "cipher",
        "server_name",
        "resumed",
        "subject",
        "issuer",
    ],
}

ZEEK_TYPES = {
    "conn": [
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "enum",
        "string",
        "interval",
        "count",
        "count",
        "string",
        "count",
        "count",
    ],
    "dns": [
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "enum",
        "string",
        "count",
        "string",
        "string",
        "string",
        "vector[string]",
        "vector[int]",
    ],
    "http": [
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "string",
        "string",
        "string",
        "string",
        "count",
        "count",
        "count",
    ],
    "ssl": [
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "string",
        "string",
        "string",
        "bool",
        "string",
        "string",
    ],
}


def _format_zeek_ts(ts: datetime) -> str:
    """Format a datetime as Zeek epoch timestamp (seconds.microseconds)."""
    epoch = ts.timestamp()
    return f"{epoch:.6f}"


def generate_zeek_log_string(log_type: str, n_events: int = 100, seed: int = 42) -> str:
    """Generate a Zeek log in TSV format as a string.

    Includes proper ``#fields`` and ``#types`` header lines.

    Args:
        log_type: One of 'conn', 'dns', 'http', 'ssl'.
        n_events: Number of event lines to generate.
        seed: Random seed for reproducibility.

    Returns:
        A string containing the full Zeek TSV log.
    """
    if log_type not in ZEEK_FIELDS:
        raise ValueError(f"Unknown log type: {log_type}")

    rng = random.Random(seed)
    fields = ZEEK_FIELDS[log_type]
    types = ZEEK_TYPES[log_type]
    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    lines: list[str] = []
    lines.append("#separator \\x09")
    lines.append("#set_separator	,")
    lines.append("#empty_field	-")
    lines.append("#unset_field	-")
    lines.append("#path	" + log_type)
    lines.append("#open	" + _format_zeek_ts(base_time))
    lines.append("#fields\t" + "\t".join(fields))
    lines.append("#types\t" + "\t".join(types))

    for i in range(n_events):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400))
        uid = _make_uid(rng)
        src_ip_raw = f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        dst_ip_raw = f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        src_ip = _pseudonymize_ip(src_ip_raw)
        dst_ip = _pseudonymize_ip(dst_ip_raw)
        src_port = rng.randint(1024, 65535)

        if log_type == "conn":
            dst_port = rng.choice(list(COMMON_PORTS.keys()))
            proto = "tcp" if dst_port in (80, 443, 22, 25, 445, 3389, 8080) else "udp"
            service = COMMON_PORTS.get(dst_port, "-")
            duration = round(rng.uniform(0.001, 10.0), 6)
            orig_bytes = rng.randint(0, 100_000)
            resp_bytes = rng.randint(0, 500_000)
            conn_state = rng.choice(["SF", "S0", "REJ", "S1", "RSTO"])
            orig_pkts = rng.randint(1, 100)
            resp_pkts = rng.randint(1, 100)
            row = [
                _format_zeek_ts(ts),
                uid,
                src_ip,
                str(src_port),
                dst_ip,
                str(dst_port),
                proto,
                service,
                str(duration),
                str(orig_bytes),
                str(resp_bytes),
                conn_state,
                str(orig_pkts),
                str(resp_pkts),
            ]
        elif log_type == "dns":
            dst_port = 53
            proto = "udp"
            query = rng.choice(DNS_DOMAINS)
            qclass = 1
            qtype = rng.choice(["A", "AAAA", "TXT", "MX", "PTR"])
            rcode = "NOERROR"
            rcode_name = "NOERROR"
            answers = "10.0.0.1"
            ttl = "300"
            row = [
                _format_zeek_ts(ts),
                uid,
                src_ip,
                str(src_port),
                dst_ip,
                str(dst_port),
                proto,
                query,
                str(qclass),
                qtype,
                rcode,
                rcode_name,
                answers,
                ttl,
            ]
        elif log_type == "http":
            dst_port = 80
            proto = "tcp"
            method = rng.choice(HTTP_METHODS)
            host = rng.choice(HTTP_HOSTS)
            uri = "/" + "".join(rng.choice("abcdef0123456789") for _ in range(8))
            user_agent = rng.choice(USER_AGENTS)
            status_code = str(rng.choice([200, 200, 200, 301, 404, 500]))
            req_len = rng.randint(0, 10_000)
            resp_len = rng.randint(0, 100_000)
            row = [
                _format_zeek_ts(ts),
                uid,
                src_ip,
                str(src_port),
                dst_ip,
                str(dst_port),
                method,
                host,
                uri,
                user_agent,
                status_code,
                str(req_len),
                str(resp_len),
            ]
        elif log_type == "ssl":
            dst_port = 443
            proto = "tcp"
            version = rng.choice(SSL_VERSIONS)
            cipher = rng.choice(SSL_CIPHERS)
            server_name = rng.choice(SSL_SERVER_NAMES)
            resumed = "F"
            subject = f"CN={server_name}"
            issuer = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US"
            row = [
                _format_zeek_ts(ts),
                uid,
                src_ip,
                str(src_port),
                dst_ip,
                str(dst_port),
                version,
                cipher,
                server_name,
                resumed,
                subject,
                issuer,
            ]
        else:
            continue

        lines.append("\t".join(row))

    lines.append("#close\t" + _format_zeek_ts(base_time + timedelta(seconds=86400)))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Zeek event object generation
# ---------------------------------------------------------------------------


def generate_zeek_conn_logs(
    n_events: int = 5000,
    anomaly_ratio: float = 0.02,
    seed: int = 42,
) -> list[ZeekConn]:
    """Generate synthetic Zeek conn.log events.

    Normal traffic: web, DNS, SSH, etc. with realistic byte/packet counts.
    Anomalies injected: scans (many destinations), exfiltration (high bytes),
    C2 beaconing (periodic connections), lateral movement (unusual ports).

    Args:
        n_events: Number of events to generate.
        anomaly_ratio: Fraction of events that are anomalies.
        seed: Random seed for reproducibility.

    Returns:
        List of ZeekConn objects with pseudonymized IPs.
    """
    rng = random.Random(seed)
    n_anomalies = max(1, int(n_events * anomaly_ratio))
    n_normal = n_events - n_anomalies
    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Pool of source hosts
    src_hosts = [_random_ip(rng, f"src-host-{i}") for i in range(20)]
    dst_hosts = [_random_ip(rng, f"dst-host-{i}") for i in range(50)]

    events: list[ZeekConn] = []

    # Normal traffic
    for i in range(n_normal):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        src_ip = rng.choice(src_hosts)
        dst_ip = rng.choice(dst_hosts)
        dst_port = rng.choice(list(COMMON_PORTS.keys()))
        proto = "tcp" if dst_port in (80, 443, 22, 25, 445, 3389, 8080) else "udp"
        service = COMMON_PORTS.get(dst_port)
        duration = round(rng.uniform(0.001, 5.0), 6)
        orig_bytes = rng.randint(100, 50_000)
        resp_bytes = rng.randint(500, 200_000)
        conn_state = rng.choice(["SF", "SF", "SF", "S0", "REJ"])
        orig_pkts = rng.randint(1, 50)
        resp_pkts = rng.randint(1, 50)
        events.append(
            ZeekConn(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=rng.randint(1024, 65535),
                dst_port=dst_port,
                protocol=proto,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                service=service,
                conn_state=conn_state,
            )
        )

    # Anomaly: scan (many unique destinations, short connections)
    scan_host = rng.choice(src_hosts)
    for i in range(n_anomalies // 4):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        events.append(
            ZeekConn(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=scan_host,
                dst_ip=_random_ip(rng, f"scan-target-{i}"),
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([22, 445, 3389, 8080]),
                protocol="tcp",
                duration=round(rng.uniform(0.001, 0.1), 6),
                orig_bytes=rng.randint(0, 100),
                resp_bytes=0,
                orig_pkts=1,
                resp_pkts=0,
                service=None,
                conn_state="S0",
            )
        )

    # Anomaly: exfiltration (high bytes out)
    exfil_host = rng.choice(src_hosts)
    for i in range(n_anomalies // 4):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        events.append(
            ZeekConn(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=exfil_host,
                dst_ip=_random_ip(rng, f"exfil-dst-{i}"),
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([443, 8080]),
                protocol="tcp",
                duration=round(rng.uniform(10.0, 300.0), 6),
                orig_bytes=rng.randint(5_000_000, 50_000_000),
                resp_bytes=rng.randint(100, 1000),
                orig_pkts=rng.randint(1000, 50000),
                resp_pkts=rng.randint(10, 100),
                service="ssl" if rng.random() > 0.5 else "http",
                conn_state="SF",
            )
        )

    # Anomaly: C2 beaconing (periodic, small connections)
    c2_host = rng.choice(src_hosts)
    c2_dst = _random_ip(rng, "c2-server")
    for i in range(n_anomalies // 4):
        ts = base_time + timedelta(seconds=i * 60)  # periodic every 60s
        events.append(
            ZeekConn(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=c2_host,
                dst_ip=c2_dst,
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([443, 8080, 8443]),
                protocol="tcp",
                duration=round(rng.uniform(0.01, 0.5), 6),
                orig_bytes=rng.randint(50, 200),
                resp_bytes=rng.randint(50, 200),
                orig_pkts=2,
                resp_pkts=2,
                service="ssl",
                conn_state="SF",
            )
        )

    # Anomaly: lateral movement (unusual ports)
    lateral_host = rng.choice(src_hosts)
    for i in range(n_anomalies - 3 * (n_anomalies // 4)):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        events.append(
            ZeekConn(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=lateral_host,
                dst_ip=_random_ip(rng, f"lateral-target-{i}"),
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([135, 139, 445, 1433, 1521, 3306, 5432, 5985]),
                protocol="tcp",
                duration=round(rng.uniform(0.1, 5.0), 6),
                orig_bytes=rng.randint(1000, 50_000),
                resp_bytes=rng.randint(1000, 50_000),
                orig_pkts=rng.randint(10, 100),
                resp_pkts=rng.randint(10, 100),
                service=None,
                conn_state="SF",
            )
        )

    rng.shuffle(events)
    log.debug(
        "conn_logs_generated",
        n_events=len(events),
        n_anomalies=n_anomalies,
        anomaly_ratio=anomaly_ratio,
    )
    return events


def generate_zeek_dns_logs(
    n_events: int = 2000,
    anomaly_ratio: float = 0.02,
    seed: int = 42,
) -> list[ZeekDNS]:
    """Generate synthetic Zeek dns.log events.

    Normal: standard A/AAAA queries to common domains.
    Anomalies: DNS tunneling (long queries, TXT records, high NXDOMAIN).

    Args:
        n_events: Number of events.
        anomaly_ratio: Fraction of anomalies.
        seed: Random seed.

    Returns:
        List of ZeekDNS objects.
    """
    rng = random.Random(seed)
    n_anomalies = max(1, int(n_events * anomaly_ratio))
    n_normal = n_events - n_anomalies
    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    src_hosts = [_random_ip(rng, f"dns-src-{i}") for i in range(20)]
    dns_servers = [_random_ip(rng, f"dns-server-{i}") for i in range(5)]

    events: list[ZeekDNS] = []

    # Normal DNS
    for i in range(n_normal):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        events.append(
            ZeekDNS(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=rng.choice(src_hosts),
                dst_ip=rng.choice(dns_servers),
                src_port=rng.randint(1024, 65535),
                dst_port=53,
                protocol="udp",
                query=rng.choice(DNS_DOMAINS),
                qclass=1,
                qtype=rng.choice(["A", "AAAA", "MX"]),
                rcode="NOERROR",
                rcode_name="NOERROR",
                answers=[f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}"],
                ttl=[rng.randint(60, 3600)],
            )
        )

    # Anomaly: DNS tunneling (long queries, TXT)
    tunnel_host = rng.choice(src_hosts)
    for i in range(n_anomalies):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        long_query = (
            "".join(
                rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(50)
            )
            + ".tunnel.evil.com"
        )
        is_nxdomain = rng.random() < 0.5
        events.append(
            ZeekDNS(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=tunnel_host,
                dst_ip=rng.choice(dns_servers),
                src_port=rng.randint(1024, 65535),
                dst_port=53,
                protocol="udp",
                query=long_query,
                qclass=1,
                qtype="TXT" if rng.random() < 0.5 else "A",
                rcode="NXDOMAIN" if is_nxdomain else "NOERROR",
                rcode_name="NXDOMAIN" if is_nxdomain else "NOERROR",
                answers=[]
                if is_nxdomain
                else [f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}"],
                ttl=[] if is_nxdomain else [rng.randint(0, 60)],
            )
        )

    rng.shuffle(events)
    log.debug(
        "dns_logs_generated",
        n_events=len(events),
        n_anomalies=n_anomalies,
    )
    return events


def generate_zeek_http_logs(
    n_events: int = 1000,
    anomaly_ratio: float = 0.02,
    seed: int = 42,
) -> list[ZeekHTTP]:
    """Generate synthetic Zeek http.log events.

    Normal: standard GET/POST to common hosts.
    Anomalies: exfiltration via large POST, C2 via HTTP.

    Args:
        n_events: Number of events.
        anomaly_ratio: Fraction of anomalies.
        seed: Random seed.

    Returns:
        List of ZeekHTTP objects.
    """
    rng = random.Random(seed)
    n_anomalies = max(1, int(n_events * anomaly_ratio))
    n_normal = n_events - n_anomalies
    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    src_hosts = [_random_ip(rng, f"http-src-{i}") for i in range(20)]
    web_servers = [_random_ip(rng, f"web-server-{i}") for i in range(10)]

    events: list[ZeekHTTP] = []

    # Normal HTTP
    for i in range(n_normal):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        events.append(
            ZeekHTTP(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=rng.choice(src_hosts),
                dst_ip=rng.choice(web_servers),
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([80, 443, 8080]),
                method=rng.choice(["GET", "GET", "GET", "POST"]),
                host=rng.choice(HTTP_HOSTS),
                uri="/" + "".join(rng.choice("abcdef0123456789") for _ in range(8)),
                user_agent=rng.choice(USER_AGENTS),
                status_code=rng.choice([200, 200, 200, 301, 404]),
                request_body_len=rng.randint(0, 5000),
                response_body_len=rng.randint(100, 50_000),
            )
        )

    # Anomaly: exfiltration via large POST
    exfil_host = rng.choice(src_hosts)
    exfil_dst = _random_ip(rng, "http-exfil-dst")
    for i in range(n_anomalies // 2):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        events.append(
            ZeekHTTP(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=exfil_host,
                dst_ip=exfil_dst,
                src_port=rng.randint(1024, 65535),
                dst_port=80,
                method="POST",
                host="upload.evil.com",
                uri="/upload",
                user_agent="curl/7.88.1",
                status_code=200,
                request_body_len=rng.randint(1_000_000, 10_000_000),
                response_body_len=rng.randint(10, 100),
            )
        )

    # Anomaly: C2 via HTTP (regular beacons)
    c2_host = rng.choice(src_hosts)
    c2_dst = _random_ip(rng, "http-c2-dst")
    for i in range(n_anomalies - n_anomalies // 2):
        ts = base_time + timedelta(seconds=i * 120)
        events.append(
            ZeekHTTP(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=c2_host,
                dst_ip=c2_dst,
                src_port=rng.randint(1024, 65535),
                dst_port=8080,
                method="GET",
                host="c2.evil.com",
                uri="/checkin",
                user_agent="Mozilla/5.0 (compatible; Bot/1.0)",
                status_code=200,
                request_body_len=0,
                response_body_len=rng.randint(50, 500),
            )
        )

    rng.shuffle(events)
    log.debug(
        "http_logs_generated",
        n_events=len(events),
        n_anomalies=n_anomalies,
    )
    return events


def generate_zeek_ssl_logs(
    n_events: int = 500,
    anomaly_ratio: float = 0.02,
    seed: int = 42,
) -> list[ZeekSSL]:
    """Generate synthetic Zeek ssl.log events.

    Normal: standard TLS to common domains.
    Anomalies: suspicious SNI, self-signed certs.

    Args:
        n_events: Number of events.
        anomaly_ratio: Fraction of anomalies.
        seed: Random seed.

    Returns:
        List of ZeekSSL objects.
    """
    rng = random.Random(seed)
    n_anomalies = max(1, int(n_events * anomaly_ratio))
    n_normal = n_events - n_anomalies
    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    src_hosts = [_random_ip(rng, f"ssl-src-{i}") for i in range(20)]
    ssl_servers = [_random_ip(rng, f"ssl-server-{i}") for i in range(10)]

    events: list[ZeekSSL] = []

    # Normal SSL
    for i in range(n_normal):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        server_name = rng.choice(SSL_SERVER_NAMES)
        events.append(
            ZeekSSL(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=rng.choice(src_hosts),
                dst_ip=rng.choice(ssl_servers),
                src_port=rng.randint(1024, 65535),
                dst_port=443,
                version=rng.choice(SSL_VERSIONS),
                cipher=rng.choice(SSL_CIPHERS),
                server_name=server_name,
                resumed=rng.random() < 0.1,
                subject=f"CN={server_name}",
                issuer="CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
            )
        )

    # Anomaly: suspicious SNI
    suspicious_host = rng.choice(src_hosts)
    for i in range(n_anomalies):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400 * 7))
        suspicious_sni = (
            "".join(
                rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(20)
            )
            + ".xyz"
        )
        events.append(
            ZeekSSL(
                timestamp=ts,
                uid=_make_uid(rng),
                src_ip=suspicious_host,
                dst_ip=_random_ip(rng, f"suspicious-ssl-{i}"),
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([443, 8443]),
                version="TLSv1.0",
                cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
                server_name=suspicious_sni,
                resumed=False,
                subject=f"CN={suspicious_sni}",
                issuer="CN=Self-Signed,O=Unknown,C=XX",
            )
        )

    rng.shuffle(events)
    log.debug(
        "ssl_logs_generated",
        n_events=len(events),
        n_anomalies=n_anomalies,
    )
    return events


def generate_all_logs(seed: int = 42) -> dict[str, list]:
    """Generate all types of Zeek logs with coordinated IPs and timestamps.

    Uses the same pool of source hosts across all log types so that
    feature engineering can correlate events per host.

    Args:
        seed: Random seed for reproducibility.

    Returns:
        Dict with keys 'conn', 'dns', 'http', 'ssl' mapping to lists.
    """
    conn = generate_zeek_conn_logs(n_events=5000, anomaly_ratio=0.02, seed=seed)
    dns = generate_zeek_dns_logs(n_events=2000, anomaly_ratio=0.02, seed=seed + 1)
    http = generate_zeek_http_logs(n_events=1000, anomaly_ratio=0.02, seed=seed + 2)
    ssl = generate_zeek_ssl_logs(n_events=500, anomaly_ratio=0.02, seed=seed + 3)

    log.debug(
        "all_logs_generated",
        conn=len(conn),
        dns=len(dns),
        http=len(http),
        ssl=len(ssl),
    )
    return {"conn": conn, "dns": dns, "http": http, "ssl": ssl}
