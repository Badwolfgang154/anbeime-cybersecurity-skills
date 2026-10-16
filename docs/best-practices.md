# Best Practices — Cyber Threat Spectrum Analysis

## Skill Authoring

1. **Start defensive**: Always frame analysis around detection and mitigation.
2. **Map to ATT&CK**: Link every behavior to a real technique for cross-referencing.
3. **Provide IOCs**: Define observable indicators (files, processes, network) that analysts can use.
4. **Keep it actionable**: Every recommendation should be implementable by a security operator.

## Content Standards

- **No exploit code**: Provide behavioral analysis, not operational payloads.
- **No bypass techniques**: Focus on detection and mitigation, not evasion.
- **Cite sources**: Reference MITRE ATT&CK techniques with links.
- **Validate references**: Ensure all file paths, hashes, and indicators are accurate.

## Usage Guidelines

- **Triage**: Use the family reference to classify an incoming threat.
- **Detection**: Combine IOCs with SIEM rules for correlation.
- **Response**: Follow the mitigation steps in order — contain, eradicate, recover.
- **Report**: Use `references/report-template.md` for consistent documentation.

## Maintenance

- Re-validate when adding new families or updating references.
- Keep `SKILL_SOURCES.json` metadata current.
- Update `README.md` stats when new skills or references are added.

## Contributing

See `CONTRIBUTING.md` for the contribution workflow.
