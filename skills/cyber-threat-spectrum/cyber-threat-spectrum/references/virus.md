# Virus

## Behavior Profile
A virus attaches itself to host files and replicates when the host is executed.
Mechanisms:
- **BIND** — appends malicious code to executable files (.exe, .dll, .scr)
- **OVERWRITE** — replaces file content while keeping minimal structure
- **STAGE** — loads a secondary payload after the host runs

Propagation requires user action (opening a file, running a program).
No autonomous network traversal.

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1547.001 | Boot or Logon: Registry Run Keys / Startup Folder |
| T1204.002 | User Execution: Malicious File |
| T1036 | Masquerading (rename to look like legitimate file) |
| T1027 | Obfuscated Files or Information |

## Detection Signature
| Category | Indicator |
|---|---|
| File | PE header anomalies, appended sections, mismatched imports |
| Process | Persists after host exits; unexpected child process |
| Registry | Run keys pointing to infected file paths |
| Network | Outbound connection to a C2 if the virus carries one |
| Fileless | Rare for classic file-infecting virus |

## Mitigation
- Maintain updated endpoint protection with file reputation scoring
- Block execution of attachments from untrusted sources
- Use application control / DEP / ASLR to limit payload execution
- Scan for unusual file modifications; keep backups offline
- Monitor for unexpected child processes after host execution
