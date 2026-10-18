# ThreatFox Integration

Read-only integration with the ThreatFox community IOC API
(https://threatfox.abuse.ch/api/). It imports public threat indicators,
normalises them to the internal IOC schema, and validates them before they can
reach the report.

## What it does

* Fetches recent IOCs via the documented `get_iocs` operation.
* Normalises each ThreatFox record to the same record shape used by the
  extractor report (`type`, `value`, `category`, `source`, `description`, plus
  preserved metadata: `remote_id`, `family`, `confidence`, `first_seen`,
  `last_seen`, `reference`, `tags`, `threat_type`, `ioc_type`).
* Validates every indicator through the extractor's own validators before it is
  admitted. A valid-looking value is **not** treated as a confirmed malicious
  indicator by itself.
* De-duplicates indicators by `(type, value)` while merging useful metadata
  (tag union, highest confidence, earliest dates).
* Is strictly read-only: it never submits IOCs, never downloads samples and
  never opens the URLs embedded in the fetched indicators.

## Prerequisites

* Python 3.8+ (stdlib only; no new package installation is required).
* A ThreatFox authentication key. You can obtain one for free from the abuse.ch
  Authentication Portal (https://auth.abuse.ch/).

## Configuration

Set the `THREATFOX_AUTH_KEY` environment variable with your key. The key must
**never** appear in code, fixtures, reports or logs.

```bash
export THREATFOX_AUTH_KEY="your-threatfox-auth-key-here"
```

You can also inject the key programmatically:

```python
from tools.threatfox_client import ThreatFoxClient

client = ThreatFoxClient(auth_key="my-key")
iocs = client.get_iocs(days=3)
```

## Usage

### Command line

```bash
# Fetch the last 3 days of IOCs (documented default), one JSON object on stdout
python tools/threatfox_client.py --days 3
```

To limit the query window, use `--days` (allowed range: **1-7**, default `3`).
The API also rejects requests with an invalid `Auth-Key`.

### Programmatically

```python
import os
os.environ["THREATFOX_AUTH_KEY"] = "your-key"

from tools.threatfox_client import ThreatFoxClient

client = ThreatFoxClient(timeout=15)
iocs = client.get_iocs(days=7)   # 1..7 inclusive
print(len(iocs), "normalized IOCs")
```

## Data collected

Each normalised record carries:

| Field | Source (ThreatFox) | Description |
|---|---|---|
| `type` | `ioc_type` | Mapped to the internal type (`domain`, `url`, `ip`, `sha256`, `sha1`, `md5`). Unsupported types (e.g. `file`) are skipped. |
| `value` | `ioc` | Original indicator value (e.g. `malware.example.com`). |
| `category` | internal map | `network` or `file`. |
| `source` | constant | Always `threatfox`. |
| `description` | `threat_type`, `threat_type_desc`, `malware`, `malware_printable` | Human-readable one-liner. |
| `remote_id` | `id` | ThreatFox record identifier. |
| `family` | `malware_printable` / `malware` | Readable malware name (e.g. `Dridex`). |
| `confidence` | `confidence_level` | 0-100 integer. |
| `first_seen` / `last_seen` | `first_seen` / `last_seen` | Original dates (UTC, as reported). |
| `reference` | `reference` | URL link when available. |
| `tags` | `tags` | ThreatFox tags. |
| `threat_type` | `threat_type` | ThreatFox threat type (e.g. `botnet_cc`). |
| `ioc_type` | `ioc_type` | Original ThreatFox type (for traceability). |

## Error handling

The client raises a specific exception for each failure mode:

| Failure mode | Exception |
|---|---|
| Missing or empty `THREATFOX_AUTH_KEY` | `ThreatFoxAuthError` |
| Non-2xx HTTP status (e.g. 403) | `ThreatFoxHttpError` |
| Request timeout / connection failure | `ThreatFoxError` (message mentions `timed out`) |
| Invalid JSON in the response | `ThreatFoxInvalidJsonError` |
| API reports `query_status: error` | `ThreatFoxError` (includes `error_message`) |
| Response schema mismatch (missing `data` list, non-object) | `ThreatFoxInvalidResponseError` |

The query window is enforced: `days` must be an integer in `[1, 7]`; anything
else raises `ThreatFoxError`.

## Limitations

* **Active is not guaranteed.** ThreatFox expires IOCs older than 6 months
  (since 2025-05-01). Expired IOCs are not returned by the API. Even within
  the returned window, the presence of an indicator in ThreatFox does **not**
  mean it is currently active or legitimate.
* **Source confidence is a hint.** `confidence_level` is published by the
  source and does not replace an analyst's verification.
* **Format validation is not a verdict.** The extractor's validators check the
  shape of an indicator, not its maliciousness. Maliciousness must be assessed
  by the analyst.
* **Type coverage.** ThreatFox `ioc_type` values such as `file` have no direct
  equivalent in the internal schema, so they are skipped.
* **Network hygiene.** The client fetches indicators but never opens the URLs
  they point to, and never downloads samples.

## Running the tests

The integration tests are offline and do not require a real key. They patch
the network layer and cover:

* a valid response with several IOC types
* an empty response
* invalid indicators and missing fields
* de-duplicated indicators (metadata preserved)
* timeouts and HTTP errors
* invalid JSON and API-reported errors
* a missing authentication key
* the documented `days` limits

```bash
python -m pytest tests/ -q
```

Expected: `57 passed` (43 existing tests from the IOC extractor, plus 14 new
ThreatFox tests).
