# 🎯 Cyber Threat Spectrum Skills

[![Stars](https://img.shields.io/github/stars/Badwolfgang154/anbeime-cybersecurity-skills?style=social)](https://github.com/Badwolfgang154/anbeime-cybersecurity-skills)
[![Forks](https://img.shields.io/github/forks/Badwolfgang154/anbeime-cybersecurity-skills?style=social)](https://github.com/Badwolfgang154/anbeime-cybersecurity-skills/network/members)
[![License](https://img.shields.io/badge/license-CC--BY--4.0-blue)](https://creativecommons.org/licenses/by/4.0/)

Cybersecurity skills package for threat classification and analysis of the full threat spectrum.

## 📊 Stats

- **Official skills**: 1 (cyber-threat-spectrum-analysis)
- **Families covered**: 10 (Virus, Worm, Trojan/RAT, Ransomware, Spyware, Adware, Rootkit, Fileless, Keylogger, Botnet)
- **MITRE ATT&CK mapped**: 30+ techniques
- **Detection guides**: 1 per family
- **License**: CC-BY-4.0

## 🧭 Structure

```
anbeime-cybersecurity-skills/
├── README.md
├── API_INTEGRATION.md
├── CONTRIBUTING.md
├── examples/
│   ├── ioc_report.json
│   └── ioc_report_splunk
├── docs/
│   ├── best-practices.md
│   ├── quickstart.md
│   ├── SIEM_EDR_Integration_Guide.md
│   ├── specification.md
│   └── threatfox-integration.md
├── hands-on/
│   └── hands-on-guide.md
├── skills/
│   └── cyber-threat-spectrum/
│       └── cyber-threat-spectrum/
│           ├── SKILL.md
│           ├── references/
│           │   ├── adware.md
│           │   ├── botnet.md
│           │   ├── fileless.md
│           │   ├── keylogger.md
│           │   ├── ransomware.md
│           │   ├── report-template.md
│           │   ├── rootkit.md
│           │   ├── spyware.md
│           │   ├── trojan-rat.md
│           │   ├── virus.md
│           │   └── worm.md
│           └── assets/
├── tests/
│   ├── fixtures/
│   │   └── synthetic_iocs.json
│   ├── test_ioc_extractor.py
│   └── test_threatfox_client.py
├── tools/
│   ├── ioc_extractor.py
│   ├── skill_validator.py
│   └── threatfox_client.py
```

## 🚀 Quick Start

```bash
git clone https://github.com/Badwolfgang154/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
# Read SKILL.md to get started
```

## 📖 Included Skills

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

## 🛠️ Contributing

See `CONTRIBUTING.md` for contributing new families or improvements.

## 📄 License

CC-BY-4.0 — Attribution required.

## Credits & Sources

### anbeime/skill (upstream)
- Upstream repository: https://github.com/anbeime/skill
- License of upstream: **CC-BY-4.0** (Creative Commons Attribution 4.0 International), per the repository badge.
- What came from here: the skill structure (`skills/<name>/<name>/SKILL.md`), the `SKILL.md` model, `report-template.md`, and the organization of threat-family references.

### Original contribution — Badwolfgang154
- Tools: `tools/ioc_extractor.py`, `tools/skill_validator.py`, `tools/threatfox_client.py`.
- Tests: `tests/test_ioc_extractor.py`, `tests/test_threatfox_client.py`.
- Documentation and project description: `README.md`, `README_EN.md`, `USAGE-GUIDE.md`, `API_INTEGRATION.md`, `QUICKSTART.md`, `CONTRIBUTING.md`, `DEPLOYMENT.md`, `DEPLOYMENT_GUIDE.md`, `DEPLOYMENT_CHECKLIST.md`, `SUMMARY.md`, `PROJECT_SUMMARY.md`, `FINAL-SUMMARY.md`, `DEMO-SUCCESS.md`, `README_EN_translated.md`.
- These files are not in the upstream `anbeime/skill`; they were added or customized by Badwolfgang154.

### MITRE ATT&CK
- Basis of the technique mapping: https://attack.mitre.org
- The families map behaviors to techniques such as T1547.001, T1204.002, T1036, T1027, etc.

### ThreatFox / abuse.ch
- Public API of compromise indicators (IOCs): https://threatfox.abuse.ch
- The `tools/threatfox_client.py` client consumes the API for read-only.

### License
- The project uses **CC-BY-4.0**.
- The upstream `anbeime/skill` indicates its license as CC-BY-4.0 in its README (no LICENSE file in the repository).
- Both are permissive and compatible; no conflict.

