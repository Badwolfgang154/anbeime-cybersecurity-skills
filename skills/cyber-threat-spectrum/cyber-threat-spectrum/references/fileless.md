# Fileless Malware

## Behavior Profile
Fileless malware executes directly in memory (RAM) without writing files to
disk, leaving fewer forensic artifacts and evading signature-based AV/signature
detection.

Mechanisms:
- **PSExec** — executes commands remotely via SMB
- **WMI** — uses Windows Management Instrumentation for silent execution
- **POWERSHELL** — runs obfuscated scripts (Base64) with Invoke-WebRequest, IEX
- **DLL_INJECT** — injects shellcode into legitimate processes (explorer.exe, svchost.exe)

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1047 | Windows Management Instrumentation |
| T1021.001 | Lateral Movement: Remote Desktop Protocol |
| T1055 | Process Injection |
| T1548 | Abuse Elevation Control |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | PowerShell/WMI child processes with encoded/command-line script content |
| Process | Legitimate processes (svchost.exe, explorer.exe) spawning unusual child processes |
| Network | Outbound connections to unknown hosts during script execution |
| Event Logs | PowerShell execution logs (4104 - script block logging); WMI activity logs |
| Memory | Unusual memory allocation from suspicious processes |

## Mitigation
- Enable PowerShell logging (script block logging, transcription)
- Run PowerShell as a constrained language mode; restrict exploitation modules
- Disable WMI persistence where not required; monitor WMI activity
- Use application allowlisting; restrict execution from temp paths
- Enable EDR memory-analyzer policies; secure credential stores (LSASS protection)
