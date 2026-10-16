# Trojan / RAT

## Behavior Profile
A trojan disguises itself as legitimate software to trick the user into
executing it. A Remote Access Trojan (RAT) goes further: it opens a
persistent, covert communication channel to a command-and-control (C2)
server, giving the attacker remote control over the infected host.

Mechanisms:
- **DISGUISE** — uses spoofed icons, renamed binaries, stolen/altered code
- **BACKDOOR** — opens a reverse connection to a C2 host
- **PAYLOAD_LOADER** — downloads and executes additional payloads on demand

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1204.001 | User Execution: Malicious File |
| T1547.001 | Boot or Logon: Registry Run Keys / Startup Folder |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking |
| T1021.001 | Lateral Movement: Remote Desktop Protocol |
| T1071.001 | Command and Control: Application Layer Protocol |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | Unexpected child processes signed with unknown certs; named like legitimate tools |
| Network | Persistent, low-volume outbound connections to unknown IPs/domains |
| Registry | Run keys / scheduled tasks loading the trojan on startup |
| File | Executables with valid but stolen signatures; unusual file names |
| System | Hidden windows, mouse/keyboard activity not initiated by user |

## Mitigation
- Deploy application allowlisting (e.g., AppLocker, WDAC)
- Block execution of unsigned binaries from user-writable locations
- Enable EDR behavior monitoring for suspicious child processes
- Filter outbound traffic; block known C2 IPs/domains; monitor for beaconing
- Audit scheduled tasks, registry run keys, and startup folders regularly
