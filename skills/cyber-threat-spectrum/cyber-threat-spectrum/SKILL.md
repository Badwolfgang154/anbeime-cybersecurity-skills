---
name: cyber-threat-spectrum-analysis
description: >
  Framework for classifying, analyzing, and managing the full spectrum of
  cybersecurity threats. Covers malware families (virus, worm, trojan,
  ransomware, spyware, adware, rootkit, fileless, keylogger) with focus on
  behavior mapping, MITRE ATT&CK technique classification, indicator
  extraction, and defensive mitigation. Built for security analysts and
  red-team operators doing threat analysis and detection engineering.
allowed-tools: Bash(git:*) Read Write
---

# Cyber Threat Spectrum Analysis

## Overview

This skill provides a structured method for classifying and analyzing the
full spectrum of cybersecurity threats that target digital environments.
It organizes threats into families, maps each to observable behaviors and
MITRE ATT&CK techniques, and defines the defensive data (indicators,
signatures, detection rules) needed to recognize and mitigate them.

The framework is used by:
- **Blue-team analysts** performing threat triage, detection engineering, and incident response
- **Red-team operators** building simulations for defense testing
- **Forensic investigators** reconstructing attack chains

## Scope

The threat spectrum is divided into nine families:

1. Virus
2. Worm
3. Trojan / RAT
4. Ransomware
5. Spyware
6. Adware
7. Rootkit
8. Fileless malware
9. Keylogger
10. Botnet

Each family is analyzed with the same four-part structure:

- **Behavior profile** — what the threat does (high-level mechanics)
- **MITRE ATT&CK mapping** — the techniques it aligns with
- **Detection signature** — indicators, logs, and artifacts to look for
- **Mitigation** — how to detect, contain, and remove the threat

## Usage

### When to use this skill

- Triaging an alert or incident by threat family
- Building detection rules (YARA, Sigma, SIEM) for a target family
- Mapping an observed attack chain to ATT&CK techniques
- Generating a threat classification report for documentation

### Workflow

1. **Identify the family** — match observed behavior to one of the nine profiles
2. **Map techniques** — align observed actions to MITRE ATT&CK
3. **Extract IOCs** — hashes, IPs, domains, registry keys, file paths
4. **Apply mitigation** — containment, eradication, recovery steps
5. **Document** — write a report following the template in `references/report-template.md`

## Reference Catalog

Each family has a dedicated reference document:

| Family | Reference |
|---|---|
| Virus | `references/virus.md` |
| Worm | `references/worm.md` |
| Trojan / RAT | `references/trojan-rat.md` |
| Ransomware | `references/ransomware.md` |
| Spyware | `references/spyware.md` |
| Adware | `references/adware.md` |
| Rootkit | `references/rootkit.md` |
| Fileless | `references/fileless.md` |
| Keylogger | `references/keylogger.md` |
| Botnet | `references/botnet.md` |

## Report Template

Use `references/report-template.md` when producing a threat analysis report.
