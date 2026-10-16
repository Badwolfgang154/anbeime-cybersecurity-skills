# Specification — Cyber Threat Spectrum Analysis

## Overview

This document defines the technical specification for the
**Cyber Threat Spectrum Analysis** skill. It covers structure, frontmatter,
validation rules, ATT&CK mapping conventions, and detection signature formats.

## Required Structure

Each skill directory must follow this layout:

```
skills/<skill-name>/<skill-name>/
├── SKILL.md                ← Core skill definition (required)
├── references/             ← Reference documentation (optional)
├── assets/                 ← Images/ assets (optional)
└── tools/                  ← Helper scripts (optional)
```

## SKILL.md Frontmatter

The SKILL.md must start with YAML frontmatter delimited by `---`:

```yaml
---
name: <skill-name>
description: <one-paragraph description of the skill>
allowed-tools: <comma-separated tool namespaces>
---
```

### Required Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Skill identifier (lowercase, hyphens) |
| `description` | string | One-paragraph description |

### Optional Fields

| Field | Type | Description |
|---|---|---|
| `allowed-tools` | string | Namespaced tools the skill may invoke |

## Markdown Content Rules

- Must contain at least one H1 (`#`) heading
- Body must be at least 10 lines
- Must use proper markdown formatting

### Recommended Sections

- Overview
- Usage
- Reference Catalog
- Report Template
- Limitations

## Reference Documentation

Reference files (`references/*.md`) should follow a consistent structure:

```markdown
# <Family Name>

## Behavior Profile
<high-level mechanics>

## MITRE ATT&CK Mapping
| Technique | Tactic |
|---|---|

## Detection Signature
| Category | Indicator |
|---|---|

## Mitigation
<response steps>
```

## Family Naming Convention

Use camelCase family names:

| Family | Reference |
|---|---|
| Virus | `virus.md` |
| Worm | `worm.md` |
| Trojan / RAT | `trojan-rat.md` |
| Ransomware | `ransomware.md` |
| Spyware | `spyware.md` |
| Adware | `adware.md` |
| Rootkit | `rootkit.md` |
| Fileless | `fileless.md` |
| Keylogger | `keylogger.md` |
| Botnet | `botnet.md` |

## Security Boundaries

This skill focuses on defensive analysis and mitigation. It does not
provide operational exploit code, payloads, or bypass techniques.
