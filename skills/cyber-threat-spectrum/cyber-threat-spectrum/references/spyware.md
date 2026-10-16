# Spyware

## Behavior Profile
Spyware silently collects information about a user or organization and
sends it to an attacker. It focuses on data harvesting rather than
encryption, destruction, or system takeover.

Mechanisms:
- **SCREENCAP** — captures screenshots periodically
- **HARVEST** — collects documents, photos, saved credentials
- **AUDIO/VIDEO** — activates microphone and webcam remotely
- **EXFIL** — sends data via DNS tunneling, HTTPS, or covert channels to C2

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1005 | Data from Local System |
| T1119 | Automated Collection |
| T1003 | Credential Dumping |
| T1074.002 | Data Staged: Remote Data Staging |
| T1567 | Exfiltration Over Web Service |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | Unknown processes reading clipboard, document folders, or consuming CPU in bursts |
| Network | Unusual outbound data transfers (large volumes to a single destination) |
| File | Suspicious persistence mechanisms; browser extensions with unknown publishers |
| System | Webcam/microphone indicators activated simultaneously |
| Logs | Browser process accessing credential stores, auto-login databases |

## Mitigation
- Enforce application allowlisting; block unapproved software
- Use ad-blockers and script blockers (uBlock Origin, NoScript)
- Keep browsers and password managers updated
- Monitor network egress for unusual data volumes
- Audit browser extensions and installed software regularly
