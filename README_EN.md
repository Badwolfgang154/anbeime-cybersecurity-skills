# Anbeime

**Cyber Threat Intelligence & IOC Extraction toolkit for Blue Team, SOC and Threat Intelligence teams.**

[![Stars](https://img.shields.io/github/stars/Badwolfgang154/anbeime-cybersecurity-skills?style=social)](https://github.com/Badwolfgang154/anbeime-cybersecurity-skills)
[![Forks](https://img.shields.io/github/forks/Badwolfgang154/anbeime-cybersecurity-skills?style=social)](https://github.com/Badwolfgang154/anbeime-cybersecurity-skills/network/members)
[![License](https://img.shields.io/badge/license-CC--BY--4.0-blue)](https://creativecommons.org/licenses/by/4.0/)

Anbeime is an open-source Python project that performs **structured threat analysis and indicator processing for defensive security**. It turns raw documentation and community threat-feed exports into normalized, validated observations and reports that analysts can actually use in a Blue Team or SOC workflow.

> The repository is a **skills pack plus tooling kit**, not a SIEM and not a malware sandbox. It prepares and structures information to support, not replace, human analysis.

## 1. Project purpose

Anbeime sits at the intersection of **Threat Intelligence (TI)** and **Blue Team / SOC operations**:

- **Intake** — parse threat references (markdown family documentation) and community feeds into a single schema.
- **Structure** — separate *concrete indicators* (hashes, domains, IPs, URLs, paths, registry keys) from *behavioral and evidential observations* (what the malware does, log artifacts, persistence points).
- **Validate** — apply strict format validation to every candidate indicator (`type`, `value`, `category`, `source`, `description`).
- **Report** — emit readable JSON and Splunk-style outputs, plus offline test fixtures.
- **Enrich conditionally** — the ThreatFox read-only client adds real external IOCs, but only when a valid API key is configured.

## 2. Where it helps (use cases)

- **Blue Team** — build detection theories and triage material before writing correlation rules.
- **SOC** — normalize threat material into a common schema for further enrichment.
- **Threat Intelligence** — convert community feeds into validated, de-duplicated indicators with full provenance.
- **Detection engineering** — feed indicator/candidate lists into detection development without manual copy-paste.

## 3. Malware families covered

| # | Family | Reference |
|---|---|---|
| 1 | Virus | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/virus.md` |
| 2 | Worm | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/worm.md` |
| 3 | Trojan / RAT | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/trojan-rat.md` |
| 4 | Ransomware | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/ransomware.md` |
| 5 | Spyware | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/spyware.md` |
| 6 | Adware | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/adware.md` |
| 7 | Rootkit | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/rootkit.md` |
| 8 | Fileless | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/fileless.md` |
| 9 | Keylogger | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/keylogger.md` |
| 10 | Botnet | `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/botnet.md` |

## 4. Observations vs. concrete Indicators of Compromise (IOCs)

This is the core distinction of the project, and it is important to be explicit.

**Concrete IOCs** are values that can be directly searched and matched: `sha256` hashes, `domain`, `ip`/`ipv4`/`ipv6`, `url`, `path`, `registry`, `event_id`, `command`.

**Behavioral and evidential observations** are high-level descriptions of what malware does, or what a defensive sensor may see: for example "unexpected child process", "beaconing pattern", "mass file creation in temp/system directories", "registry persistence key used by a known-good Windows service". They describe **patterns and artifacts**, not directly queryable values.

Anbeime's extractor (`tools/ioc_extractor.py`) produces three record kinds:

- `iocs` — normalized indicators with `type`, `value`, `category`, `source`, `description`.
- `behaviors` — behavioral observations (type `behavior`).
- `evidence` — evidential observations (type `evidence`), including detection-relevant log IDs only when explicit event-log context is present in the reference text.

**Transparency — current state:** the analysis references bundled with the project currently contain **0 concrete IOCs**; all 10 families produce behavioral/evidential observations only (for example, 26 behaviors and 10 evidence records across the families). Concrete indicators are produced when (a) a reference document contains a matchable IOC pattern, or (b) the ThreatFox client returns external IOCs.

**Important:** format validation is **not** a verdict. An indicator that passes format validation is an *unverified candidate* — never a confirmed malicious indicator.

## 5. Tools reference

### tools/ioc_extractor.py

**Purpose:** scans the family references in `skills/cyber-threat-spectrum/cyber-threat-spectrum/references`, extracts IOC / behavior / evidence records, validates them, and writes the reports.

**CLI arguments (confirmed in code):**

| Argument | Short | Values / type | Description |
|---|---|---|---|
| `--family` | `-f` | string | Analyze only one family (example: `--family ransomware`). |
| `--format` | `-o` | `json` / `splunk` / `all`, default `json` | Output format. |
| `--all` | `-a` | flag | Extract all families (default behaviour; the "all" value of `--format` also includes it). |
| `--output-dir` | `-O` | path, default current directory | Directory for the generated reports. |

**Outputs (confirmed by the `main()` implementation):**

- `ioc_report.json` — JSON format (`--format json` or `--format all`).
- `ioc_report_splunk` — CSV-style format (`--format splunk` or `--format all`).

**Working directory:** the tools resolve `tools/` and `skills/` relative to `Path.cwd()`, so they must be run from the **repository root**.

**JSON format** (`ioc_report.json`, generated by `format_json`):

- Top level: `generated_at`, `tool` (`"ioc_extractor"`), `schema_version` (`"2.0.0"`).
- `summary`: `families_analyzed`, `total_iocs`, `total_behaviors`, `total_evidence`, `total_observations`.
- `families`: array of family records, each with `family`, `reference`, `ioc_count`, `behavior_count`, `evidence_count`, `total_observations`, and the nested arrays `iocs`, `behaviors`, `evidence`.

**Splunk format** (`ioc_report_splunk`, generated by `format_splunk`):

- One CSV-style line per **concrete IOC**: `family | category | type | value | description | reference`.
- Behaviors and evidence are **never** rendered in the Splunk output.

### tools/skill_validator.py

**Purpose:** validates the skill structure, the YAML frontmatter of `SKILL.md`, and the markdown body requirements (at least one H1, at least 10 body lines, references directory populated with `.md` files).

**CLI arguments (confirmed in code):**

| Argument | Type | Description |
|---|---|---|
| `--validate` | flag | Run repository-wide validation. |
| `path` | optional positional | Validate a single skill directory. |

Exit code 0 on success, 1 on validation failure.

### tools/threatfox_client.py

**Purpose:** read-only client for the ThreatFox community IOC API. Fetches recent IOCs, normalizes them into the same schema as the extractor, validates them, and de-duplicates them.

**CLI arguments (confirmed in code):**

| Argument | Type | Values / default | Description |
|---|---|---|---|
| `--days` | int | 1–7, default 3 | Days window for the `get_iocs` operation. |
| `--timeout` | int | 10, default 10 | Network timeout in seconds. |
| `--out` | path | stdout by default | Write the JSON report to this file instead of stdout. |

**Environment variable:**

- `THREATFOX_AUTH_KEY` — the ThreatFox authentication key. The client refuses to run without a non-empty key and never prints the key or any other stored credential.

**API details (confirmed in code):**

- Base URL: `https://threatfox-api.abuse.ch/api/v1/`
- Operation: HTTP POST `{"query": "get_iocs", "days": N}` with the header `Auth-Key`.
- Allowed `days` range: 1–7 (default 3); anything else raises a documented error.
- Read-only guarantees: it never submits IOCs, never downloads samples, and never opens URLs embedded in the fetched indicators.

## 6. Installation & dependencies

- **Python:** 3.8+ recommended (the ThreatFox documentation explicitly targets Python 3.8+, stdlib only).
- `tools/ioc_extractor.py` — Python standard library only (`argparse`, `ipaddress`, `json`, `re`, `uuid`, `datetime`, `pathlib`).
- `tools/threatfox_client.py` — Python standard library only (`argparse`, `json`, `os`, `urllib`).
- `tools/skill_validator.py` — requires **PyYAML** (install with `pip install pyyaml`).
- **Tests:** `pytest` (install with `pip install pytest`).

No new dependencies are required to run the extractor or the ThreatFox client.

## 7. Quick start (commands confirmed in the current code)

```bash
git clone https://github.com/Badwolfgang154/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills
```

Run the extractor from the **repository root**:

```bash
# Generate both reports (JSON + Splunk) in ./relatorios
python3 tools/ioc_extractor.py --format all --output-dir ./relatorios

# Extract a single family only
python3 tools/ioc_extractor.py --family ransomware

# JSON only, current directory
python3 tools/ioc_extractor.py --format json

# Splunk only
python3 tools/ioc_extractor.py --format splunk
```

Validate the skill:

```bash
python3 tools/skill_validator.py --validate
```

Query ThreatFox (read-only) — requires `THREATFOX_AUTH_KEY` to be defined:

```bash
export THREATFOX_AUTH_KEY="your-threatfox-auth-key-here"
python3 tools/threatfox_client.py --days 3 --out threatfox.json
```

Run the tests:

```bash
python3 -m pytest tests/ -q
```

## 8. Data formats

### JSON — `ioc_report.json`

Generated by `format_json` in `tools/ioc_extractor.py`: pretty-printed JSON (2-space indentation), UTF-8, `ensure_ascii=False`. Structure described in section 5 (`tools/ioc_extractor.py`).

### Splunk — `ioc_report_splunk`

Generated by `format_splunk` in `tools/ioc_extractor.py`. CSV-style, one line per concrete IOC:

```
ransomware | network | domain | malware.example.com | Description of the indicator | skills/cyber-threat-spectrum/cyber-threat-spectrum/references/ransomware.md
```

Only concrete IOCs are rendered — the extractor's `iocs` arrays. The current reference set contains 0 concrete IOCs, so the generated `ioc_report_splunk` file is empty (0 bytes); it becomes populated whenever indicators are actually extracted.

## 9. ThreatFox integration

- **Read-only:** never submits IOCs, never downloads samples, never opens URLs embedded in fetched indicators.
- Fetches the documented `get_iocs` operation for a configurable window (default: last 3 days, allowed range 1–7).
- Normalizes each record into the extractor's schema: `type`, `value`, `category`, `source` (`"threatfox"`), `description`, `remote_id`, `family`, `confidence`, `first_seen`, `last_seen`, `reference`, `tags`, `threat_type`, `ioc_type`.
- Validates every normalized indicator with the same format validators used by the extractor (`is_valid_domain`, `is_valid_ip`, `is_valid_hash`, `is_valid_url`).
- De-duplicates by `(type, value)`, merging tags (union), keeping the highest confidence, and keeping the earliest dates.
- Unsupported ThreatFox types (for example `file`) have no direct equivalent in the internal schema and are skipped.

**Prerequisites:**

- Python 3.8+ (stdlib only).
- An API key from the abuse.ch Authentication Portal: https://auth.abuse.ch/

**Setup:**

```bash
export THREATFOX_AUTH_KEY="your-threatfox-auth-key-here"
```

The key **never** appears in code, fixtures, reports, or logs. The client raises `ThreatFoxAuthError` if the key is missing or empty; non-2xx responses raise `ThreatFoxHttpError`, timeouts raise `ThreatFoxError`, and malformed responses raise the specific invalid-* error classes.

## 10. Automated tests

- `tests/test_ioc_extractor.py` — schema consistency, false positives, separation of behaviors, IOC counting, validation functions, de-duplication, JSON/Splunk consistency, and synthetic fixture samples.
- `tests/test_threatfox_client.py` — offline; patches the network layer. Covers valid responses with several IOC types, empty responses, invalid indicators, de-duplicated indicators, HTTP errors, timeouts, invalid JSON, API-reported errors, missing authentication key, and the documented `days` limits.
- `tests/conftest.py` — session fixture that runs the extractor in a temporary directory and returns the paths of `ioc_report.json` and `ioc_report_splunk`.

Run with:

```bash
python3 -m pytest tests/ -q
```

## 11. Project structure

```text
anbeime-cybersecurity-skills/
├── README.md
├── README_EN.md
├── API_INTEGRATION.md
├── CONTRIBUTING.md
├── QUICKSTART.md
├── USAGE-GUIDE.md
├── SKILL_SOURCES.json
├── examples/
│   ├── ioc_report.json
│   └── ioc_report_splunk
├── docs/
│   ├── best-practices.md
│   ├── quickstart.md
│   ├── SIEM_EDR_Integration_Guide.md
│   ├── specification.md
│   └── threatfox-integration.md
├── hands-on/
│   └── hands-on-guide.md
├── skills/
│   └── cyber-threat-spectrum/
│       └── cyber-threat-spectrum/
│           ├── SKILL.md
│           ├── references/
│           │   ├── adware.md
│           │   ├── botnet.md
│           │   ├── fileless.md
│           │   ├── keylogger.md
│           │   ├── ransomware.md
│           │   ├── report-template.md
│           │   ├── rootkit.md
│           │   ├── spyware.md
│           │   ├── trojan-rat.md
│           │   ├── virus.md
│           │   └── worm.md
│           └── assets/
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   └── synthetic_iocs.json
│   ├── test_ioc_extractor.py
│   └── test_threatfox_client.py
└── tools/
    ├── ioc_extractor.py
    ├── skill_validator.py
    └── threatfox_client.py
```

## 12. Limitations & good practices

- **Observations ≠ confirmed IOCs.** The current reference set produces behavioral and evidential observations; treat them as candidates, not as blacklisted values.
- **Format ≠ malicious.** A value that passes validation is an unverified candidate.
- **ThreatFox coverage.** Unsupported `ioc_type` values (for example `file`) are skipped; the feed may also stop returning IOCs older than 6 months.
- **Source confidence is a hint.** `confidence_level` is published by the source and does not replace analyst verification.
- **Documentation-driven.** The extractor reflects the reference Markdown files; when the documentation changes, the reports change too.
- **Environment hygiene.** Never commit API keys, `.env` files, or `*.key` files — `.gitignore` excludes them.
- **Run from the repository root.** The tools resolve `tools/`, `skills/`, and `references/` relative to the current working directory.

## 13. Security & responsible use

- The ThreatFox client is **read-only**.
- The extractor never downloads samples, executes code, or opens URLs found in references.
- All credential material (API keys) is external to the repository and must be supplied via the environment.
- **All results are candidates / observations and require human validation** before they are used in detection rules, threat feeds, or incident response.

## 14. License

This project is licensed under **CC-BY-4.0** (Attribution required).

## 15. Credits & sources

### anbeime/skill (upstream)

- Upstream repository: https://github.com/anbeime/skill
- License: **CC-BY-4.0** (as indicated in the upstream README; no LICENSE file in the repository).
- Origin: skill structure (`skills/<name>/<name>/SKILL.md`), the `SKILL.md` model, `report-template.md`, and the organization of threat-family references.

### Original contribution — Badwolfgang154

- Tools: `tools/ioc_extractor.py`, `tools/skill_validator.py`, `tools/threatfox_client.py`.
- Tests: `tests/test_ioc_extractor.py`, `tests/test_threatfox_client.py`.
- Documentation and project description: `README.md`, `README_EN.md`, `USAGE-GUIDE.md`, `API_INTEGRATION.md`, `QUICKSTART.md`, `CONTRIBUTING.md`, `docs/` files.

### MITRE ATT&CK

- Technique mapping basis: https://attack.mitre.org

### ThreatFox / abuse.ch

- Public IOC API: https://threatfox.abuse.ch
- API documentation: https://threatfox.abuse.ch/api/
- Authentication portal: https://auth.abuse.ch/

### License

- Project: **CC-BY-4.0** (permissive, compatible).
- Upstream: **CC-BY-4.0**.

## 16. Links

- Repository: https://github.com/Badwolfgang154/anbeime-cybersecurity-skills
- Upstream: https://github.com/anbeime/skill
- MITRE ATT&CK: https://attack.mitre.org
- ThreatFox: https://threatfox.abuse.ch
- abuse.ch authentication: https://auth.abuse.ch/
- Project documentation: `docs/` folder
