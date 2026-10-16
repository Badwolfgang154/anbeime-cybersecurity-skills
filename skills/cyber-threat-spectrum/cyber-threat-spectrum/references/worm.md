# Worm

## Behavior Profile
A worm is self-propagating malware that spreads across networks without user
interaction or a host file. It operates autonomously.

Mechanisms:
- **SCAN** — probes IPs/subnets for vulnerable services
- **EXPLOIT** — leverages known vulnerabilities to gain access
- **COPY** — replicates binary to remote systems via SMB, FTP, email
- **DAEMON** — installs a persistent service on the remote host

Worms are often used for initial network-wide compromise, data exfiltration,
or as a delivery vector for secondary payloads.

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1021.002 | Lateral Movement: SMB/Windows Admin Shares |
| T1569.002 | Execution: Service Execution |
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1071.001 | Command and Control: Application Layer Protocol |
| T1046 | Network Service Discovery |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | Unusual child processes scanning ports; repeated SMB/FTP connections |
| Network | High volume of outbound scans to multiple hosts; unusual SMB traffic |
| File | Mass creation of executables in temp or system dirs |
| Registry | Newly created services designed to self-replicate |
| Logs | Repeated connection failures followed by success on the same port |

## Mitigation
- Patch systems and services promptly (esp. SMTP, SMB, RDP, DNS)
- Restrict lateral movement: disable SMB admin shares, enforce least privilege
- Segment the network to limit worm propagation
- Deploy network detection rules for scan-to-exploit sequences
- Keep offline backups for recovery; isolate infected hosts immediately
