# Adware

## Behavior Profile
Adware generates revenue by serving unwanted advertisements. While less
destructive than ransomware or rootkit-class malware, it degrades system
performance, risks secondary infection, and can indicate poor security
hygiene.

Mechanisms:
- **INJECT** — injects banner pop-ups or redirects into browsers
- **REDIRECT** — hijacks traffic to affiliate sites to generate clicks
- **MINING** — optionally uses CPU/GPU for light cryptocurrency mining

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1204.001 | User Execution: Malicious File |
| T1056.001 | Input Capture: Keylogging (if credential-stealing variant) |
| T1071.001 | Command and Control: Application Layer Protocol |
| T1057 | Process Discovery |

## Detection Signature
| Category | Indicator |
|---|---|
| Browser | Unwanted pop-ups; homepage/dns changed; excessive redirects |
| File | Browser extensions from unknown publishers |
| Network | Redirects to affiliate domains; excessive outbound requests |
| Process | Miners consuming high CPU; coin-miner binaries in temp dirs |
| User | Browser homepage reset without user action |

## Mitigation
- Keep browsers and plugins updated; remove unused extensions
- Use reputable ad-blocking extensions; avoid freeware bundles
- Verify software distribution sources (prefer official sites)
- Apply browser security policies (Content Security Policy, extension controls)
- Monitor process CPU usage for mining activity
