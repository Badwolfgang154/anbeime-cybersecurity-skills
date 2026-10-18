"""Tests for the ThreatFox integration (tools/threatfox_client.py).

These tests are fully offline and require no real API key.  They patch the
network layer and assert against the client's behaviour so that the
integration can be fuzz-tested without touching ThreatFox or the internet.
"""

import io
import json
import os
import socket
import sys
import urllib.error
from unittest import mock

import pytest

# Make `ioc_extractor` (used for the format validators) importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "tools"))

import threatfox_client  # noqa: E402

AUTH_ENV = threatfox_client.AUTH_ENV
AUTH_HEADER = threatfox_client.AUTH_HEADER

# Fields that every normalised IOC record must carry.
REQUIRED_IOC_FIELDS = {"type", "value", "category", "source", "description"}

VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _payload(data):
    return {"query_status": "ok", "data": data}


class FakeResponse:
    """Minimal file-like object that behaves like a urllib response."""

    def __init__(self, payload_bytes):
        self._payload = payload_bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._payload


def _client(auth_key="test-key"):
    return threatfox_client.ThreatFoxClient(auth_key=auth_key)


# ---------------------------------------------------------------------------
# 1. Valid response with several IOC types
# ---------------------------------------------------------------------------

def test_valid_response_normalises_multiple_types():
    payload = _payload(
        [
            {
                "id": "101",
                "ioc": "malware.example.com",
                "threat_type": "botnet_cc",
                "ioc_type": "domain",
                "malware": "win.dridex",
                "malware_printable": "Dridex",
                "confidence_level": 50,
                "first_seen": "2026-01-01 12:00:00 UTC",
                "last_seen": None,
                "reference": "https://twitter.com/abc/status/1",
                "reporter": "abuse_ch",
                "tags": ["test"],
            },
            {
                "id": "102",
                "ioc": "9.9.9.9:4444",
                "threat_type": "botnet_cc",
                "ioc_type": "ip:port",
                "malware": "win.rabbit",
                "malware_printable": "Rabbit",
                "confidence_level": 70,
                "first_seen": "2026-01-02 12:00:00 UTC",
                "tags": [],
            },
            {
                "id": "103",
                "ioc": VALID_SHA256,
                "threat_type": "payload_delivery",
                "ioc_type": "sha256",
                "malware": "win.zloader",
                "malware_printable": "Zloader",
                "confidence_level": 80,
                "first_seen": "2026-01-03 12:00:00 UTC",
                "tags": ["exe"],
            },
            {
                "id": "104",
                "ioc": "https://payload.example/download",
                "threat_type": "payload_delivery",
                "ioc_type": "url",
                "malware": "win.zloader",
                "malware_printable": "Zloader",
                "confidence_level": 80,
                "first_seen": "2026-01-03 12:00:00 UTC",
                "tags": ["exe"],
            },
        ]
    )

    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(json.dumps(payload).encode("utf-8"))
        iocs = _client().get_iocs(days=3)

    assert len(iocs) == 4
    for ioc in iocs:
        assert REQUIRED_IOC_FIELDS <= set(ioc.keys())

    domains = [ioc for ioc in iocs if ioc["type"] == "domain"]
    assert len(domains) == 1
    assert domains[0]["value"] == "malware.example.com"
    assert domains[0]["category"] == "network"
    assert domains[0]["family"] == "Dridex"
    assert domains[0]["remote_id"] == "101"
    assert domains[0]["threat_type"] == "botnet_cc"
    assert domains[0]["tags"] == ["test"]

    ips = [ioc for ioc in iocs if ioc["type"] == "ip"]
    assert len(ips) == 1
    assert ips[0]["value"] == "9.9.9.9"  # ip:port -> ip
    assert ips[0]["confidence"] == 70

    hashes = [ioc for ioc in iocs if ioc["type"] == "sha256"]
    assert len(hashes) == 1
    assert hashes[0]["value"] == VALID_SHA256

    urls = [ioc for ioc in iocs if ioc["type"] == "url"]
    assert len(urls) == 1
    assert urls[0]["value"] == "https://payload.example/download"


# ---------------------------------------------------------------------------
# 2. Empty response
# ---------------------------------------------------------------------------

def test_empty_response_returns_no_iocs():
    payload = _payload([])

    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(json.dumps(payload).encode("utf-8"))
        iocs = _client().get_iocs(days=3)

    assert iocs == []


# ---------------------------------------------------------------------------
# 3. Invalid indicators and missing fields are filtered out
# ---------------------------------------------------------------------------

def test_invalid_iocs_and_missing_fields_are_filtered():
    payload = _payload(
        [
            {
                "id": "1",
                "ioc_type": "domain",
                "ioc": "explorer.exe",  # executable-looking TLD
                "malware_printable": "E",
                "confidence_level": 50,
                "first_seen": "2026-01-01 12:00:00 UTC",
            },
            {
                "id": "2",
                "ioc_type": "md5",
                "ioc": "d41d8cd98f00b204e9800998ecf8427",  # 31 chars, not MD5
                "malware_printable": "E",
                "confidence_level": 50,
                "first_seen": "2026-01-02 12:00:00 UTC",
            },
            {
                "id": "3",
                "ioc_type": "domain",
                "first_seen": "2026-01-03 12:00:00 UTC",  # missing "ioc"
            },
            {"id": "4"},  # missing ioc_type and ioc
        ]
    )

    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(json.dumps(payload).encode("utf-8"))
        iocs = _client().get_iocs(days=3)

    assert iocs == []


# ---------------------------------------------------------------------------
# 4. Duplicate indicators are merged without losing metadata
# ---------------------------------------------------------------------------

def test_duplicate_indicators_are_merged_and_meta_preserved():
    payload = _payload(
        [
            {
                "id": "1",
                "ioc": "dup.example.com",
                "ioc_type": "domain",
                "malware_printable": "Alpha",
                "confidence_level": 40,
                "first_seen": "2026-01-01 12:00:00 UTC",
                "tags": ["a", "b"],
            },
            {
                "id": "2",
                "ioc": "dup.example.com",
                "ioc_type": "domain",
                "malware_printable": "Beta",
                "confidence_level": 90,
                "first_seen": "2026-01-02 12:00:00 UTC",
                "tags": ["c"],
            },
        ]
    )

    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(json.dumps(payload).encode("utf-8"))
        iocs = _client().get_iocs(days=3)

    assert len(iocs) == 1
    record = iocs[0]
    assert record["value"] == "dup.example.com"
    # Tags union, duplicates removed.
    assert sorted(record["tags"]) == ["a", "b", "c"]
    # Highest confidence kept.
    assert record["confidence"] == 90
    # Earliest date kept.
    assert record["first_seen"] == "2026-01-01 12:00:00 UTC"


# ---------------------------------------------------------------------------
# 5. HTTP errors and timeouts
# ---------------------------------------------------------------------------

def test_http_error_is_reported():
    body = b'{"query_status":"error","error_message":"invalid Auth-Key"}'
    exc = urllib.error.HTTPError(
        "https://threatfox-api.abuse.ch/api/v1/", 403, "Forbidden", {}, io.BytesIO(body)
    )

    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.side_effect = exc
        with pytest.raises(threatfox_client.ThreatFoxHttpError) as excinfo:
            _client().get_iocs(days=3)

    assert "403" in str(excinfo.value)


def test_timeout_is_reported():
    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError(reason=socket.timeout("timed out"))
        with pytest.raises(threatfox_client.ThreatFoxError) as excinfo:
            _client().get_iocs(days=3)

    assert "timed out" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# 6. Malformed payloads
# ---------------------------------------------------------------------------

def test_invalid_json_is_reported():
    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(b"{not valid json")
        with pytest.raises(threatfox_client.ThreatFoxInvalidJsonError):
            _client().get_iocs(days=3)


def test_api_error_status_is_reported():
    payload = {"query_status": "error", "error_message": "missing Auth-Key"}

    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(json.dumps(payload).encode("utf-8"))
        with pytest.raises(threatfox_client.ThreatFoxError) as excinfo:
            _client().get_iocs(days=3)

    assert "missing Auth-Key" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 7. Missing authentication key
# ---------------------------------------------------------------------------

def test_missing_auth_key_raises():
    with mock.patch.dict(os.environ, {}, clear=True):
        client = threatfox_client.ThreatFoxClient(auth_key="")
        with pytest.raises(threatfox_client.ThreatFoxAuthError):
            client.get_iocs(days=3)


# ---------------------------------------------------------------------------
# 8. Query limits documented by the API (days 1..7)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("invalid_days", [0, -1, 8, "not-a-number"])
def test_days_respect_documented_limits(invalid_days):
    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(
            json.dumps(_payload([])).encode("utf-8")
        )
        with pytest.raises(threatfox_client.ThreatFoxError):
            _client().get_iocs(days=invalid_days)


def test_days_within_limits_is_accepted():
    with mock.patch.object(
        threatfox_client.urllib.request, "urlopen"
    ) as mock_urlopen:
        mock_urlopen.return_value = FakeResponse(
            json.dumps(_payload([])).encode("utf-8")
        )
        iocs = _client().get_iocs(days=3)
        assert iocs == []
