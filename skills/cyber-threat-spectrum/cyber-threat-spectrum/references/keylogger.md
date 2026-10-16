# Keylogger

## Behavior Profile
A keylogger captures every keystroke typed by the user and records them —
this includes passwords, messages, and sensitive data entered into forms.
Modern keyloggers can also capture screenshots, clipboard content, and
autofilled credentials.

Mechanisms:
- **HOOK_KEYBOARD** — intercepts keyboard messages via Native API hooks
- **SCREENSHOT_SYNC** — pairs screenshots with keystrokes for context
- **CREDENTIAL_HARVEST** — captures form autofill data before it is sent
- **PRIVACY_MODE** — hides cursor or masked text to avoid user suspicion

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1056.001 | Input Capture: Keylogging |
| T1005 | Data from Local System |
| T1003 | Credential Dumping |
| T1552 | Unsecured Credentials |
| T1567 | Exfiltration Over Web Service |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | Low-level keyboard hooks associated with unknown processes |
| File | Legitimate-looking binaries that read keyboard/mouse event logs |
| Network | Keystroke data exfiltrating to an external destination |
| System | Clipboard content captured; screen content dumped |
| User | Login delays; unexpected window focus changes |

## Mitigation
- Use endpoint protection with kernel-level keylogger detection
- Prefer password managers with autofill security; avoid typing sensitive
  credentials on shared systems
- Enforce MFA to limit the value of captured credentials
- Keep OS and security software updated; audit installed software
- Use EDR keystroke-driver and input-capture monitoring
