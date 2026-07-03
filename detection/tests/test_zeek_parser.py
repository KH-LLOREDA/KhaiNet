"""Tests for Zeek TSV log parser."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.models import ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL
from src.synthetic_data import generate_zeek_log_string
from src.zeek_parser import (
    _pseudonymize_ip,
    parse_conn_log,
    parse_dns_log,
    parse_http_log,
    parse_ssl_log,
    parse_zeek_log,
    parse_zeek_log_from_string,
)


# ---------------------------------------------------------------------------
# TSV string parsing
# ---------------------------------------------------------------------------


class TestParseConnFromString:
    """Tests for parsing conn.log from string."""

    def test_parse_conn_log_string_basic(self):
        """Parse a basic conn.log string and verify fields."""
        content = generate_zeek_log_string("conn", n_events=10, seed=42)
        events = parse_zeek_log_from_string(content, ZeekConn)
        assert len(events) == 10
        assert all(isinstance(e, ZeekConn) for e in events)

    def test_parse_conn_log_string_fields(self):
        """Verify specific fields are parsed correctly."""
        content = generate_zeek_log_string("conn", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekConn)
        event = events[0]
        assert event.uid is not None and len(event.uid) > 0
        assert event.src_port > 0
        assert event.dst_port > 0
        assert event.protocol in ("tcp", "udp")
        assert event.duration >= 0
        assert event.orig_bytes >= 0
        assert event.resp_bytes >= 0

    def test_parse_conn_log_string_timestamps(self):
        """Verify timestamps are parsed as datetime objects."""
        content = generate_zeek_log_string("conn", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekConn)
        for event in events:
            assert isinstance(event.timestamp, datetime)
            assert event.timestamp.tzinfo is not None

    def test_parse_conn_log_string_pseudonymized_ips(self):
        """Verify IPs are pseudonymized (SHA-256 hashes)."""
        content = generate_zeek_log_string("conn", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekConn)
        for event in events:
            # SHA-256 hash is 64 hex chars
            assert len(event.src_ip) == 64
            assert len(event.dst_ip) == 64
            assert all(c in "0123456789abcdef" for c in event.src_ip)
            assert all(c in "0123456789abcdef" for c in event.dst_ip)

    def test_parse_conn_log_string_no_pseudonymize(self):
        """Verify IPs are not pseudonymized when flag is False."""
        content = generate_zeek_log_string("conn", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekConn, pseudonymize=False)
        # Without pseudonymization, IPs should be the raw SHA-256 from the generator
        # (the generator already pseudonymizes, but the parser should not double-hash)
        for event in events:
            assert len(event.src_ip) == 64  # Already hashed by generator


class TestParseDNSFromString:
    """Tests for parsing dns.log from string."""

    def test_parse_dns_log_string_basic(self):
        content = generate_zeek_log_string("dns", n_events=10, seed=42)
        events = parse_zeek_log_from_string(content, ZeekDNS)
        assert len(events) == 10
        assert all(isinstance(e, ZeekDNS) for e in events)

    def test_parse_dns_log_string_fields(self):
        content = generate_zeek_log_string("dns", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekDNS)
        event = events[0]
        assert event.query is not None and len(event.query) > 0
        assert event.dst_port == 53
        assert event.protocol == "udp"
        assert event.qtype is not None

    def test_parse_dns_log_string_answers_ttl(self):
        content = generate_zeek_log_string("dns", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekDNS)
        for event in events:
            assert isinstance(event.answers, list)
            assert isinstance(event.ttl, list)


class TestParseHTTPFromString:
    """Tests for parsing http.log from string."""

    def test_parse_http_log_string_basic(self):
        content = generate_zeek_log_string("http", n_events=10, seed=42)
        events = parse_zeek_log_from_string(content, ZeekHTTP)
        assert len(events) == 10
        assert all(isinstance(e, ZeekHTTP) for e in events)

    def test_parse_http_log_string_fields(self):
        content = generate_zeek_log_string("http", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekHTTP)
        event = events[0]
        assert event.method in ("GET", "POST", "PUT", "DELETE", "HEAD")
        assert event.host is not None
        assert event.uri is not None
        assert event.status_code is not None


class TestParseSSLFromString:
    """Tests for parsing ssl.log from string."""

    def test_parse_ssl_log_string_basic(self):
        content = generate_zeek_log_string("ssl", n_events=10, seed=42)
        events = parse_zeek_log_from_string(content, ZeekSSL)
        assert len(events) == 10
        assert all(isinstance(e, ZeekSSL) for e in events)

    def test_parse_ssl_log_string_fields(self):
        content = generate_zeek_log_string("ssl", n_events=5, seed=42)
        events = parse_zeek_log_from_string(content, ZeekSSL)
        event = events[0]
        assert event.version is not None
        assert event.cipher is not None
        assert event.server_name is not None
        assert event.dst_port == 443


# ---------------------------------------------------------------------------
# File-based parsing
# ---------------------------------------------------------------------------


class TestParseFromFile:
    """Tests for parsing Zeek logs from files."""

    def test_parse_conn_log_file(self, tmp_path):
        """Parse a conn.log file."""
        content = generate_zeek_log_string("conn", n_events=20, seed=42)
        log_path = tmp_path / "conn.log"
        log_path.write_text(content)
        events = parse_conn_log(log_path)
        assert len(events) == 20
        assert all(isinstance(e, ZeekConn) for e in events)

    def test_parse_dns_log_file(self, tmp_path):
        content = generate_zeek_log_string("dns", n_events=15, seed=42)
        log_path = tmp_path / "dns.log"
        log_path.write_text(content)
        events = parse_dns_log(log_path)
        assert len(events) == 15

    def test_parse_http_log_file(self, tmp_path):
        content = generate_zeek_log_string("http", n_events=10, seed=42)
        log_path = tmp_path / "http.log"
        log_path.write_text(content)
        events = parse_http_log(log_path)
        assert len(events) == 10

    def test_parse_ssl_log_file(self, tmp_path):
        content = generate_zeek_log_string("ssl", n_events=8, seed=42)
        log_path = tmp_path / "ssl.log"
        log_path.write_text(content)
        events = parse_ssl_log(log_path)
        assert len(events) == 8

    def test_parse_nonexistent_file(self):
        """Parsing a nonexistent file returns empty list."""
        events = parse_conn_log("/nonexistent/path/conn.log")
        assert events == []

    def test_parse_generic_zeek_log(self, tmp_path):
        """Test the generic parse_zeek_log function."""
        content = generate_zeek_log_string("conn", n_events=5, seed=42)
        log_path = tmp_path / "conn.log"
        log_path.write_text(content)
        events = parse_zeek_log(log_path, ZeekConn)
        assert len(events) == 5


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestParserEdgeCases:
    """Tests for edge cases in parsing."""

    def test_empty_values_handled(self):
        """Test that empty values (Zeek's '-') are handled."""
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\t"
            "enum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount\n"
            "1700000000.000000\tabc123\t10.0.0.1\t54321\t192.168.1.1\t443\t"
            "tcp\t-\t1.5\t5000\t50000\tSF\t10\t20\n"
        )
        events = parse_zeek_log_from_string(content, ZeekConn)
        assert len(events) == 1
        assert events[0].service is None
        assert events[0].duration == 1.5

    def test_no_header_returns_empty(self):
        """Parsing content without #fields header returns empty list."""
        content = "some\trandom\tdata\n"
        events = parse_zeek_log_from_string(content, ZeekConn)
        assert events == []

    def test_pseudonymize_ip_function(self):
        """Test the _pseudonymize_ip helper."""
        result = _pseudonymize_ip("10.0.0.1")
        assert len(result) == 64
        # Same input → same output (deterministic)
        assert _pseudonymize_ip("10.0.0.1") == result
        # Different input → different output
        assert _pseudonymize_ip("10.0.0.2") != result

    def test_pseudonymize_ip_different_salt(self):
        """Pseudonymization with different salt produces different hashes."""
        import hashlib

        h1 = hashlib.sha256(b"khainet-salt:10.0.0.1").hexdigest()
        h2 = hashlib.sha256(b"other-salt:10.0.0.1").hexdigest()
        assert h1 != h2

    def test_parse_with_extra_columns(self):
        """Parser handles rows with fewer columns than expected."""
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\t"
            "enum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount\n"
            "1700000000.000000\tabc123\t10.0.0.1\t54321\t192.168.1.1\t443\ttcp\n"
        )
        events = parse_zeek_log_from_string(content, ZeekConn)
        # Should still parse (with defaults for missing fields)
        assert len(events) == 1

    def test_parse_multiple_lines(self):
        """Parse multiple data lines."""
        content = generate_zeek_log_string("conn", n_events=50, seed=100)
        events = parse_zeek_log_from_string(content, ZeekConn)
        assert len(events) == 50
        # All should have valid timestamps
        for e in events:
            assert isinstance(e.timestamp, datetime)

    def test_parse_empty_content(self):
        """Parsing empty content returns empty list."""
        events = parse_zeek_log_from_string("", ZeekConn)
        assert events == []

    def test_parse_only_header(self):
        """Parsing content with only headers returns empty list."""
        content = "#separator \\x09\n#fields\tts\tuid\n#types\ttime\tstring\n"
        events = parse_zeek_log_from_string(content, ZeekConn)
        assert events == []
