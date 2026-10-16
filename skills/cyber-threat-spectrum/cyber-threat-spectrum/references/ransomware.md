# Ransomware

## Behavior Profile
Ransomware encrypts the victim's data and demands payment for the decryption
key. Modern ransomware operates as a pipeline: enumeration, process killing,
backup destruction, encryption, and extortion.

Mechanisms:
- **ENUM** — maps network drives, shared folders, backup locations
- **CRYPTO** — asymmetric (RSA/ECC) to protect the master key; symmetric
  (AES-GCM) to encrypt individual files
- **PREPROCESS** — kills backup and AV processes before encryption
- **NOTE** — drops a ransom note (HTML/text) with payment instructions and
  a key that must be paid in cryptocurrency

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|
| T1486 | Data Encrypted for Impact |
| T1489 | Service Stop |
| T1070.004 | Indicator Removal: Timestamps |
| T1210 | Exploitation of Remote Services |
| T1036 | Masquerading |
| T1005 | Data from Local System |

## Detection Signature
| Category | Indicator |
|---|---|
| Process | VSS admin / wbadmin / taskkill executed in sequence; mass file renames |
| File | Sudden mass renames with new extensions (.locked, .encrypted); rapid file growth |
| System | Backup service stopped; shadow copies deleted (vssadmin delete shadows) |
| File | .HTML ransom note dropped; unique extension on encrypted files |
| Network | Encrypted data exfiltration before encryption (double extortion) |

## Mitigation
- Maintain offline, immutable backups (3-2-1 rule); test restoration
- Patch and harden perimeter; disable macros in untrusted documents
- Apply anti-ransomware controls: application allowlisting, restricted permissions
- Monitor for encryption behavior markers (rapid file modification, shadow deletion)
- Isolate affected hosts immediately; do not pay if backups are intact
