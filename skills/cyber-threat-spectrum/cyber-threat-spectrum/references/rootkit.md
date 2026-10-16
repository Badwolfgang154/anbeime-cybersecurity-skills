# Rootkit

## Behavior Profile
A rootkit hides its presence (and that of other malware) from the operating
system and security tooling. It achieves stealth by hooking system calls and
modifying the data structures that listing utilities read.

Mechanisms:
- **HOOK** — intercepts system calls (SSDT on Windows, syscall on Linux)
- **MASK** — hides files, processes, and network connections from ls, ps, netstat
- **PERSIST** — installs in the boot sector or as a kernel driver (KMD)
- **ANTI-FORENSIC** — clears event logs and alters timestamps

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1543 | Create or Modify System Process |
| T1021.002 | Lateral Movement: SMB/Windows Admin Shares |
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1005 | Data from Local System |
| T1003 | Credential Dumping |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | Processes not visible in Task Manager but consuming CPU/memory |
| Network | Connections not showing in netstat; sockets missing from ss |
| File | Files inaccessible from File Explorer despite existing on disk |
| System | Timezone/date manipulation; event logs cleared without cause |
| Boot | Unauthorized boot-sector or kernel driver signed with unknown certs |

## Mitigation
- Keep the OS and kernel fully patched
- Use anti-tamper security products that monitor kernel integrity (EDR, HIDS)
- Boot from a known-good recovery environment when rootkit suspected
- Use driver-signature enforcement + WDAC/AppLocker to block unsigned kexes
- Maintain clean, offline backups for recovery
