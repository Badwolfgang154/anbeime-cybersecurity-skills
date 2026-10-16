# Botnet

## Behavior Profile
A botnet is a network of compromised devices (bots/zombies) under the control
of a single operator (botmaster) via a Command-and-Control (C2) infrastructure.
Unlike standalone malware, its defining trait is *scale* and *coordination*.

Mechanisms:
- **RECRUIT** — compromises additional hosts using exploits, phishing, or
  credential dumping; each new host joins the network
- **C2** — maintains a command-and-control channel (HTTP, IRC, DNS, custom
  protocol, or P2P mesh) to receive instructions
- **ORCHESTRATE** — executes coordinated actions across the bot population:
  DDoS, spam, credential theft, propagation, cryptomining
- **PERSIST** — maintains access across reboots and attempts at removal;
  uses diverse persistence methods (registry, services, WMI, scheduled tasks)

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1562.002 | Impair Defenses: Disable or Modify Tools |
| T1003 | Credential Dumping |
| T1021.002 | Lateral Movement: SMB/Windows Admin Shares |
| T1071 | Command and Control |
| T1486 | Data Encrypted for Impact (DDoS/Double-extortion variants) |
| T1562.001 | Impair Defenses: Disable or Modify Tools |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | High child-process count; processes spawning multiple shell instances |
| Network | Beaconing patterns — periodic, low-frequency outbound connections; DNS tunneling; IRC/P2P-like traffic |
| File | Multiple copies of the same binary on different hosts; oddly similar checksums |
| Registry | Common persistence keys across compromised hosts |
| Event Logs | Repeated identical process creations and network connections across many hosts |

## Mitigation
- Monitor for beaconing behavior with network detection rules (baselines:
  inter-arrival time, payload size, entropy)
- Maintain a blocklist of known C2 domains/IPs; block DNS tunneling and
  unusual outbound patterns
- Enforce application allowlisting; restrict lateral movement (SMB, RDP)
- Audit and offload privileged credentials; rotate secrets on suspected
  compromise
- Deploy NDR (network detection and response) to field operator traffic
- Maintain offline backups; isolate compromised hosts quickly
