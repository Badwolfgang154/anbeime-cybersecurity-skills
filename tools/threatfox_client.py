"""ThreatFox community API client (read-only).

Standalone integration with the ThreatFox community IOC API
(https://threatfox.abuse.ch/api/).  The client fetches recently published
indicators and normalises them into the internal IOC schema used by
:mod:`tools.ioc_extractor`, while validating every indicator before it is
accepted.

This module is deliberately free of third-party dependencies: it only uses the
Python standard library.  It is a read-only client -- it never submits IOCs,
never downloads samples and never opens network links embedded in the fetched
indicators.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

__all__ = [
    "DEFAULT_DAYS",
    "MAX_DAYS",
    "MIN_DAYS",
    "THREATFOX_API_BASE",
    "AUTH_HEADER",
    "AUTH_ENV",
    "ThreatFoxAuthError",
    "ThreatFoxError",
    "ThreatFoxHttpError",
    "ThreatFoxInvalidJsonError",
    "ThreatFoxInvalidResponseError",
    "ThreatFoxClient",
]

# Public ThreatFox community API endpoint (documented at
# https://threatfox.abuse.ch/api/).
THREATFOX_API_BASE = "https://threatfox-api.abuse.ch/api/v1/"

# Documented limits for the `days` filter on the `get_iocs` operation.
MIN_DAYS = 1
MAX_DAYS = 7
DEFAULT_DAYS = 3

# Default network timeout in seconds.  Kept short so that a misconfigured or
# unreachable host fails fast.
DEFAULT_TIMEOUT = 10

# Authentication header required by the ThreatFox API, and the environment
# variable that carries the key.
AUTH_HEADER = "Auth-Key"
AUTH_ENV = "THREATFOX_AUTH_KEY"

# Mapping of ThreatFox `ioc_type` values to the internal IOC `type`.  ThreatFox
# also reports types such as "file" that have no direct equivalent in the
# internal schema; those are rejected and never promoted to an IOC.
IOC_TYPE_MAP = {
    "domain": "domain",
    "url": "url",
    "ip": "ip",
    "ip:port": "ip",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}

# Category per internal type (must match the extractor's TYPE_TO_CATEGORY).
TYPE_TO_CATEGORY: Dict[str, str] = {
    "ipv4": "network",
    "ipv6": "network",
    "ip": "network",
    "domain": "network",
    "url": "network",
    "sha256": "file",
    "sha1": "file",
    "md5": "file",
    "path": "file",
    "registry": "registry",
    "event_id": "log",
    "command": "command",
    "behavior": "behavior",
    "evidence": "evidence",
}


# Import the extractor's validators so ThreatFox IOCs are filtered through the
# same format rules used for the reference-based extraction.  The dependency is
# one-way (`ioc_extractor` never imports this module), so there is no risk of a
# circular import.
from ioc_extractor import (
    is_valid_domain,
    is_valid_hash,
    is_valid_ip,
    is_valid_url,
)


class ThreatFoxError(Exception):
    """Base class for all ThreatFox integration errors."""



class ThreatFoxAuthError(ThreatFoxError):
    """Authentication key is missing or empty."""


class ThreatFoxHttpError(ThreatFoxError):
    """The API answered with a non-2xx HTTP status."""


class ThreatFoxInvalidJsonError(ThreatFoxError):
    """The API response could not be parsed as JSON."""


class ThreatFoxInvalidResponseError(ThreatFoxError):
    """The API response did not match the documented schema."""


def _env_auth_key() -> Optional[str]:
    """Read the ThreatFox authentication key from the environment."""
    return os.getenv(AUTH_ENV)


def _normalize_value(value: Any) -> str:
    """Normalise a raw field to a trimmed string."""
    if value is None:
        return ""
    return str(value).strip()


def _split_ip_port(value: str) -> str:
    """Extract the IP part from a ThreatFox `ip:port` indicator."""
    candidate, separator, port = value.rpartition(":")
    if separator and port.isdigit():
        return candidate.strip()
    return _normalize_value(value)


def _has_auth_key(auth_key: Optional[str]) -> bool:
    return auth_key is not None and auth_key.strip() != ""


def _build_request(days: int, auth_key: str) -> urllib.request.Request:
    """Build the POST request for the documented `get_iocs` operation."""
    payload = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    headers = {
        AUTH_HEADER: auth_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    return urllib.request.Request(
        THREATFOX_API_BASE, data=payload, headers=headers, method="POST"
    )


class ThreatFoxClient:
    """Read-only client for the ThreatFox community IOC API."""

    def __init__(self, auth_key: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.auth_key = auth_key if _has_auth_key(auth_key) else _env_auth_key()
        self.timeout = timeout

    # -- public API -----------------------------------------------------

    def get_iocs(self, days: int = DEFAULT_DAYS) -> List[Dict[str, Any]]:
        """Fetch recent ThreatFox IOCs, normalise and validate them.

        Returns a list of normalised IOC records matching the internal schema.
        Indicators that fail format validation, that use an unsupported IOC
        type, or that are missing mandatory fields are dropped.  Records are
        de-duplicated by (type, value) while retaining any useful metadata.
        """
        days = self._validate_days(days)
        if not _has_auth_key(self.auth_key):
            raise ThreatFoxAuthError(
                f"ThreatFox authentication key is required. Set the {AUTH_ENV} environment variable."
            )
        request = _build_request(days, self.auth_key)
        raw = self._perform_request(request)
        records = self._parse_response(raw)
        out: List[Dict[str, Any]] = []
        for record in records:
            normalised = self._normalise(record)
            if normalised is not None:
                out.append(normalised)
        return self._dedupe(out)

    # -- internal helpers ----------------------------------------------

    def _validate_days(self, days: int) -> int:
        try:
            days = int(days)
        except (TypeError, ValueError) as exc:
            raise ThreatFoxError(
                f"days must be an integer, got: {days!r}"
            ) from exc
        if days < MIN_DAYS or days > MAX_DAYS:
            raise ThreatFoxError(
                f"days must be between {MIN_DAYS} and {MAX_DAYS} (inclusive), got: {days}"
            )
        return days

    def _perform_request(self, request: urllib.request.Request) -> str:
        """Execute the POST request and return the raw response body."""
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace").strip()
            raise ThreatFoxHttpError(
                f"ThreatFox API returned HTTP {exc.code}: {body[:200]}"
            ) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError):
                raise ThreatFoxError("ThreatFox request timed out") from exc
            raise ThreatFoxError(f"ThreatFox request failed: {reason}") from exc
        except TimeoutError as exc:
            raise ThreatFoxError("ThreatFox request timed out") from exc

    def _parse_response(self, raw: str) -> List[Dict[str, Any]]:
        """Validate the response schema and return the `data` array."""
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ThreatFoxInvalidJsonError(
                f"ThreatFox API returned invalid JSON: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise ThreatFoxInvalidResponseError(
                "ThreatFox API responded with a non-object JSON value"
            )

        if payload.get("query_status") == "error":
            raise ThreatFoxError(
                f"ThreatFox API error: {payload.get('error_message', 'unknown error')}"
            )

        data = payload.get("data")
        if not isinstance(data, list):
            raise ThreatFoxInvalidResponseError(
                "ThreatFox API response is missing a 'data' list"
            )
        return data

    def _normalise(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert one ThreatFox record to the internal IOC schema.

        Returns None when the record is unusable (missing indicator, unsupported
        type, invalid value, missing mandatory fields).
        """
        ioc_type = _normalize_value(record.get("ioc_type"))
        internal_type = IOC_TYPE_MAP.get(ioc_type)
        if internal_type is None:
            # Unsupported ThreatFox type (e.g. "file").
            return None

        raw_value = _normalize_value(record.get("ioc"))
        if not raw_value:
            return None

        value = raw_value
        if internal_type == "ip" and ioc_type == "ip:port":
            value = _split_ip_port(raw_value)

        description = self._make_description(record)
        if not description:
            return None

        # Format validation: an indicator is never promoted to an IOC merely
        # because its shape matches a known pattern.
        if not self._validate_value(internal_type, value):
            return None

        return {
            "type": internal_type,
            "value": value,
            "category": TYPE_TO_CATEGORY.get(internal_type, "network"),
            "source": "threatfox",
            "description": description,
            # Preserved metadata from the source record.
            "remote_id": record.get("id"),
            "family": self._family_from(record),
            "confidence": record.get("confidence_level"),
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "reference": record.get("reference"),
            "tags": record.get("tags"),
            "threat_type": record.get("threat_type"),
            "ioc_type": ioc_type,
        }

    def _make_description(self, record: Dict[str, Any]) -> str:
        """Build a human readable description from the raw ThreatFox fields."""
        parts: List[str] = []
        threat = _normalize_value(record.get("threat_type")) or _normalize_value(
            record.get("threat_type_desc")
        )
        if threat:
            parts.append(f"Threat type: {threat}")
        malware = _normalize_value(record.get("malware_printable")) or _normalize_value(
            record.get("malware")
        )
        if malware:
            parts.append(f"Malware: {malware}")
        if not parts:
            parts.append("Indicator observed in the ThreatFox community feed")
        return " | ".join(parts)

    @staticmethod
    def _family_from(record: Dict[str, Any]) -> Optional[str]:
        """Extract a readable malware family name (no default when absent)."""
        for key in ("malware_printable", "malware"):
            value = _normalize_value(record.get(key))
            if value:
                return value
        return None

    def _validate_value(self, ioc_type: str, value: str) -> bool:
        """Apply the extractor's own validators to a normalised indicator."""
        if ioc_type == "domain":
            return is_valid_domain(value)
        if ioc_type in ("ip", "ipv4", "ipv6"):
            return is_valid_ip(value)
        if ioc_type in ("sha256", "sha1", "md5"):
            return is_valid_hash(ioc_type, value)
        if ioc_type == "url":
            return is_valid_url(value)
        return True

    @staticmethod
    def _dedupe(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """De-duplicate indicators by (type, value).

        Keeping the first occurrence and merging any useful metadata that is
        present on later duplicates (tags union, highest confidence, earliest
        dates), so nothing useful is lost.
        """
        merged: Dict[tuple, Dict[str, Any]] = {}
        order: List[tuple] = []
        for record in records:
            key = (record["type"], record["value"])
            if key in merged:
                merged[key] = ThreatFoxClient._merge(merged[key], record)
                continue
            merged[key] = dict(record)
            order.append(key)
        return [merged[key] for key in order]

    @staticmethod
    def _merge(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        existing.setdefault("tags", []).extend(incoming.get("tags") or [])
        existing["tags"] = list(dict.fromkeys(existing["tags"]))
        existing["confidence"] = max(
            existing.get("confidence") or 0,
            incoming.get("confidence") or 0,
        )
        for field in ("remote_id", "family", "reference", "first_seen", "last_seen"):
            if existing.get(field) in (None, "") and incoming.get(field):
                existing[field] = incoming[field]
        return existing


def threatfox_ioc_to_report_record(normalised_ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a normalised ThreatFox IOC into the report family record shape."""
    return {
        "type": normalised_ioc["type"],
        "value": normalised_ioc["value"],
        "category": normalised_ioc["category"],
        "source": normalised_ioc["source"],
        "description": normalised_ioc["description"],
        "remote_id": normalised_ioc.get("remote_id"),
        "family": normalised_ioc.get("family"),
        "confidence": normalised_ioc.get("confidence"),
        "first_seen": normalised_ioc.get("first_seen"),
        "last_seen": normalised_ioc.get("last_seen"),
        "reference": normalised_ioc.get("reference"),
        "tags": normalised_ioc.get("tags"),
        "threat_type": normalised_ioc.get("threat_type"),
    }


def build_threatfox_report(days: int = DEFAULT_DAYS) -> Dict[str, Any]:
    """Build a ThreatFox IOC report fragment.

    The fragment follows the same family record shape used by the extractor
    report, so the two can be merged downstream.

    Every record has already been validated by
    :meth:`ThreatFoxClient._normalise`, so this builder only converts the
    records into the family record shape and sets the fragment counters.
    """
    client = ThreatFoxClient()
    iocs = client.get_iocs(days)

    family = {
        "family": "threatfox",
        "reference": "external: threatfox.abuse.ch",
        "ioc_count": len(iocs),
        "behavior_count": 0,
        "evidence_count": 0,
        "total_observations": len(iocs),
        "iocs": [threatfox_ioc_to_report_record(ioc) for ioc in iocs],
        "behaviors": [],
        "evidence": [],
    }
    return {"families": [family]}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="ThreatFox IOC importer (read-only). "
        "Fetches recent public IOCs from ThreatFox and normalises them to the "
        "internal IOC schema."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        help=f"days window (1-{MAX_DAYS}, default {DEFAULT_DAYS})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="network timeout in seconds (default 10)",
    )
    parser.add_argument(
        "--out",
        help="write the JSON report to this file instead of stdout",
    )
    args = parser.parse_args(argv)

    if not _has_auth_key(os.getenv(AUTH_ENV)):
        parser.error(
            f"ThreatFox authentication key is required. Set the {AUTH_ENV} "
            "environment variable."
        )

    client = ThreatFoxClient(auth_key=os.getenv(AUTH_ENV), timeout=args.timeout)
    try:
        iocs = client.get_iocs(args.days)
    except ThreatFoxError as exc:
        parser.error(f"ThreatFox error: {exc}")

    payload: Dict[str, Any] = {
        "query": "get_iocs",
        "days": args.days,
        "timeout_seconds": args.timeout,
        "count": len(iocs),
        "iocs": [threatfox_ioc_to_report_record(ioc) for ioc in iocs],
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"ThreatFox: wrote {len(iocs)} IOCs to {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
