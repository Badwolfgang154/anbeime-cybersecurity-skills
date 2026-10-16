# SIEM/EDR Integration Guide — Cyber Threat Spectrum Analysis

## Objective

This guide explains how to extract Indicators of Compromise (IOCs) from the
Cyber Threat Spectrum references and feed them into SIEM/EDR platforms for
detection, threat hunting, and incident response.

## 1. IOC Extractor Tool

The repository includes an automated IOC extractor:

```
tools/ioc_extractor.py
```

### Usage

```bash
# Extract all families to JSON
python tools/ioc_extractor.py --format json > ioc_report.json

# Extract a specific family
python tools/ioc_extractor.py --family ransomware --format splunk

# Extract to a file
python tools/ioc_extractor.py --all --format json
```

### IOC Categories Produced

| Category | Description |
|---|---|
| `file` | Files, paths, hashes, ransom notes |
| `registry` | Persistence keys, boot configurations |
| `process` | Processes, command lines, behavior |
| `network` | Connections, beaconing, exfiltration |
| `command` | Command lines executed |
| `log` | Log events (e.g., PowerShell 4104) |

## 2. Splunk Integration

### Method 1: Simple CSV import

The extractor outputs Splunk-style CSV:

```bash
python tools/ioc_extractor.py --format splunk > ioc_splunk.csv
```

Load into Splunk:

```spl
| makeresults
| appendpipe [
  | inputlookup append=true
  | table *
]
```

Better:

```spl
| makeresults
| eval _raw="ransomware|file|New file extensions|.locked, .encrypted|Descrição|SERVIÇOS/cyber-threat-spectrum/cyber-threat-spectrum/references/ransomware.md"
| split _
| table *
| table *
```

### Method 2: Lookup file

Export a CSV with a header:

```csv
family,category,type,value,description,reference
ransomware,file,"New file extensions",".locked, .encrypted","Novas extensões em arquivos"
ransomware,process,"vssadmin delete shadows","Comando para excluir shadows","SERVIÇOS/cyber-threat-spectrum/cyber-threat-spectrum/references/ransomware.md"
```

Then import as a lookup:

```spl
| inputlookup addprefix ioc_
| table family category type value description reference
```

### Method 3: Siem integration answer (Splunk)

```spl
| tstats summariesonly=false values(sourcetype) as sources where index=*) by sourcetype
```

## 3. Sigma Rules Integration

Sigma is a generic signature format that works with multiple SIEMs
(Splunk, Elastic, Microsoft Sentinel, etc.).

### Example: Ransomware Detection Rule

Create `rules/ransomware.yml`:

```yaml
title: Ransomware File Encryption Activity
id: c7d7a7f5-1234-5678-90ab-cdef12345678
status: experimental
description: Detect ransomware encryption activity indicators
author: security-team
references:
  - https://github.com/Badwolfgang154/anbeime-cybersecurity-skills
date: 2026/10/16
tags:
  - attack.impact
  - attack.t1486
  - ransomware

logsource:
  category: process
  product: windows

detection:
  selection:
    Image: |
      -vssadmin.exe delete shadows
      -wbadmin.exe delete
      -cipher /w
      -cmd.exe /c reg add
    CommandLine|endswith:
      - "vssadmin delete shadows"
      - "wbadmin delete"
      - "cipher /w /a"
  condition: selection
  filter:
    Image|endswith:
      - "\vssadmin.exe"
      - "\wbadmin.exe"

falsepositives:
  - Legitimate system administrators

level: high
```

### Convert JSON to Sigma

Use a converter script to transform the `ioc_report.json` into Sigma YAML.

### Methods per SIEM

| SIEM | Integration method |
|---|---|
| **Splunk** | Import via UI or `inputlookup` |
| **Elastic** | Ingest via API or Filebeat |
| **Microsoft Sentinel** | Use Azure Logic App to sync |
| **CrowdStrike** | Use Falcon IQ or integrations |
| **Tanium** | Use IAM or IoT integration |
| **Carbon Black** | Use IntSights or custom API |

## 4. Example IOC Feed for Ransomware Detection

| IOC Type | Value | Category | Detection Tip |
|---|---|---|---|
| Process | `vssadmin delete shadows` | process | Block or alert on this command |
| Process | `wbadmin delete` | process | Alert + review user context |
| File | `.locked`, `.encrypted` | file | Watch for mass file renames |
| File | `README.html`, `*_DECRYPT.txt` | file | Look for ransom notes |
| File | `vssadmin.exe`, `wbadmin.exe` | file | Malicious binaries in temp |
| Network | Data exfiltration before encryption | network | Monitor egress volume |

### Alerting Recommendations

| IOC | Alert Level | Action |
|---|---|---|
| `vssadmin delete shadows` | High | Immediate containment |
| `wbadmin delete` | High | Immediate containment |
| Mass file renames with new extensions | Critical | Block network, isolate host |
| Ransom note dropped | High | Investigate, isolate |
| Shadow copy deletion | High | Review before accepting |

## 5. Threat Hunting Queries

### Splunk

```spl
| tstats summariesonly=false values(sourcetype) as sources where index=*) by sourcetype
| search "vssadmin" OR "wbadmin" OR "cipher /w"
| stats count by host, user, command
```

### Elastic

```json
{
  "query": {
    "bool": {
      "should": [
        { "match": { "process.command_line": "vssadmin" } },
        { "match": { "process.command_line": "wbadmin" } },
        { "match": { "file.extension": "locked" } }
      ]
    }
  }
}
```

### CrowdStrike

```sql
SELECT host, user, command_line, timestamp
FROM Process
WHERE command_line LIKE "%vssadmin%" OR command_line LIKE "%wbadmin%"
```

## 6. Maintenance

- Re-run `ioc_extractor.py` monthly to refresh the IOC feed
- Update the `KNOWN_IOCS` map when new families are added
- Validate IOCs against threat intelligence feeds (VirusTotal, AbuseIPDB, etc.)
- Review false positives with the hunt team quarterly

## 7. Security Considerations

- Store IOC feeds in a secure location accessible only to the SOC
- Rotate IOCs that reference external IPs/domains periodically
- Monitor for unauthorized access to the IOC repository
- Keep the `ioc_extractor.py` tool in version control with the skill

---

*This integration guide is part of the Cyber Threat Spectrum Analysis skill package.*
