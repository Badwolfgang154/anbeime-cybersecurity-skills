# Threat Analysis Report Template

## Headers
- **Report ID**: `{date}-{client}-{number}`
- **Analyst**: Name / role
- **Date**: ISO 8601
- **Threat family**: Virus / Worm / Trojan / Ransomware / Spyware / Adware / Rootkit / Fileless / Keylogger

## Summary
- **Objective**: What triggered the analysis (alert, incident, report)?
- **Findings**: One-paragraph summary of the threat type and scope.
- **Severity**: Critical / High / Medium / Low

## Methodology
1. Observation captured
2. Traces collected (logs, memory, network, filesystem)
3. Family mapped to reference
4. MITRE ATT&CK techniques identified

## Evidence
- **Hashes**: SHA-256, MD5, etc.
- **IPs / domains**: C2, beacon endpoints
- **File paths**: Execution locations
- **Registry keys**: Persistence locations
- **Command lines**: Notable process invocations

## MITRE ATT&CK Mapping
| Technique | Tactic | Observed? | Notes |
|---|---|---|---|
| T#### | Tactic | Yes/No | Notes |

## Indicators of Compromise
- **File IOCs**: `{hash} - {path}`
- **Network IOCs**: `{ip}:{port} - {domain}`
- **Registry IOCs**: `{path}`
- **Log IOCs**: `{log_source} - {event_id}`

## Response
- **Containment**: {action}
- **Eradication**: {action}
- **Recovery**: {action}
- **Lessons learned**: {action}

## References
- MITRE ATT&CK: https://attack.mitre.org/
- Repository: https://github.com/anbeime/skill
- Report date: {date}
