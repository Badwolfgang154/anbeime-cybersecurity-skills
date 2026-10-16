# Quickstart — Cyber Threat Spectrum Analysis

## 1. Clone the Repository

```bash
git clone https://github.com/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills
```

## 2. Explore the Skills Directory

```bash
ls -R skills/
```

You will find:

```
skills/cyber-threat-spectrum/cyber-threat-spectrum/
├── SKILL.md
└── references/
    ├── virus.md
    ├── worm.md
    ├── trojan-rat.md
    ├── ransomware.md
    ├── spyware.md
    ├── adware.md
    ├── rootkit.md
    ├── fileless.md
    ├── keylogger.md
    └── botnet.md
```

## 3. Read the Main Skill

```bash
cat skills/cyber-threat-spectrum/cyber-threat-spectrum/SKILL.md
```

## 4. Pick a Family

Open any reference:

```bash
cat skills/cyber-threat-spectrum/cyber-threat-spectrum/references/ransomware.md
```

## 5. Use the Report Template

```bash
cat skills/cyber-threat-spectrum/cyber-threat-spectrum/references/report-template.md
```

Copy it and fill in the details to produce a threat analysis report.

## 📦 Optional Tools

```bash
cd tools
pip install -r requirements.txt
python skill_validator.py validate skills/cyber-threat-spectrum
```

## ✅ Verification

After setup, verify:

- [ ] Skills directory exists
- [ ] SKILL.md has valid YAML frontmatter
- [ ] References directory contains 10 families
- [ ] Reading the skill does not require external dependencies
