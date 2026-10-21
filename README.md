# 🎯 Cyber Threat Spectrum Skills

[![Stars](https://img.shields.io/github/stars/Badwolfgang154/anbeime-cybersecurity-skills?style=social)](https://github.com/Badwolfgang154/anbeime-cybersecurity-skills)
[![Forks](https://img.shields.io/github/forks/Badwolfgang154/anbeime-cybersecurity-skills?style=social)](https://github.com/Badwolfgang154/anbeime-cybersecurity-skills/network/members)
[![License](https://img.shields.io/badge/license-CC--BY--4.0-blue)](https://creativecommons.org/licenses/by/4.0/)

Pacote de habilidades de segurança cibernética para análise e classificação do espectro completo de ameaças.

## 📊 Estatísticas

- **Habilidades oficiais**: 1 (cyber-threat-spectrum-analysis)
- **Famílias cobertas**: 10 (Vírus, Verme, Trojan/RAT, Ransomware, Spyware, Adware, Rootkit, Fileless, Keylogger, Botnet)
- **MITRE ATT&CK mapeado**: 30+ técnicas
- **Guias de detecção**: 1 por família
- **Licença**: CC-BY-4.0

## 🛡️ Sobre o Anbeime

O Anbeime — Cybersecurity Skills é um projeto de cibersegurança desenvolvido em Python, voltado à análise de ameaças, ao processamento de indicadores de comprometimento (Indicators of Compromise — IOCs) e à organização de informações úteis para atividades de segurança defensiva.

O objetivo é automatizar parte do trabalho de identificação, validação e organização de indicadores, tornando os dados mais estruturados e facilitando seu uso em investigações de segurança.

### Como funciona?

O projeto combina referências documentadas sobre famílias de ameaças com recursos de processamento de IOCs.

- Análise de referências: processa arquivos Markdown que documentam famílias de ameaças, comportamentos e evidências relevantes.
- Extração e validação de IOCs: identifica indicadores suportados e verifica se seus valores possuem formatos aceitáveis, como domínios, endereços IP, hashes e URLs.
- Normalização: padroniza os valores para facilitar o processamento consistente.
- Inteligência de ameaças: inclui um cliente para consultar a API comunitária da ThreatFox, permitindo obter indicadores externos quando a integração está configurada.
- Deduplicação: consolida indicadores repetidos e combina metadados relevantes.
- Relatórios JSON: organiza os resultados em dados estruturados, incluindo estatísticas e informações sobre as famílias analisadas.

### O que são IOCs?

Indicadores de comprometimento são artefatos ou valores que podem ajudar a investigar atividades potencialmente maliciosas.

Exemplos incluem:

- Domínios: nomes de domínio associados a atividades suspeitas.
- Endereços IP: endereços relacionados a uma infraestrutura potencialmente maliciosa.
- Hashes: identificadores calculados a partir de arquivos, úteis para comparação e investigação.
- URLs: endereços que podem estar relacionados a campanhas ou recursos maliciosos.

Um indicador isolado não confirma necessariamente um comprometimento. Os resultados precisam ser interpretados considerando o contexto, a origem e as demais evidências disponíveis.

### Aplicação em cibersegurança

O Anbeime foi pensado como um projeto de aprendizado e automação aplicável a conceitos de Blue Team, SOC e Threat Intelligence.

Seu desenvolvimento envolve práticas como:

- Consumo de APIs e processamento de dados externos.
- Validação e normalização de entradas.
- Tratamento de erros e respostas inesperadas.
- Testes automatizados com cenários simulados.
- Geração de relatórios estruturados.
- Versionamento e documentação com Git e GitHub.

O projeto não é um SIEM completo nem determina, sozinho, se um sistema foi comprometido. Sua finalidade é ajudar a preparar e organizar informações que possam apoiar análises defensivas.

### Estado do desenvolvimento

O projeto já conta com um extrator de IOCs, validadores, geração de relatórios e um cliente para a API comunitária da ThreatFox, acompanhado de testes automatizados.

A próxima etapa é consolidar essas capacidades em um fluxo unificado, preservando a procedência dos indicadores e registrando claramente o estado das consultas externas.

O desenvolvimento é incremental: novas funcionalidades devem ser acompanhadas de testes, documentação e verificações de compatibilidade.

## 🧭 Estrutura

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
## 🚀 Instalação Rápida

```bash
git clone https://github.com/Badwolfgang154/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
# Leia SKILL.md para começar
```

## Como usar

### Clonar e ler a habilidade
```bash
git clone https://github.com/Badwolfgang154/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
# Leia SKILL.md para começar
```

### Ferramentas (`tools/`)
```bash
# Extrai IOCs de todas as famílias (salva ioc_report.json)
python3 tools/ioc_extractor.py

# Extrai apenas uma família (ex.: ransomware)
python3 tools/ioc_extractor.py --family ransomware

# Valida a estrutura das skills (requer PyYAML)
python3 tools/skill_validator.py --validate

# Consulta a ThreatFox (somente leitura; não envia nenhum IOC)
python3 tools/threatfox_client.py --days 3 --out threatfox.json
```

### Testes
```bash
python3 -m pytest tests/ -v
```

> **Observação — ThreatFox:** a consulta só funciona com a chave de API disponível em `THREATFOX_AUTH_KEY`. Sem ela, a ferramenta informa o erro em vez de enviar credenciais. Os demais valores de exemplo são placeholders e não são secretos reais.

## 📖 Habilidades Incluídas

| Família | Referência |
|---|---|
| Virus | `references/virus.md` |
| Verme | `references/worm.md` |
| Trojan / RAT | `references/trojan-rat.md` |
| Ransomware | `references/ransomware.md` |
| Spyware | `references/spyware.md` |
| Adware | `references/adware.md` |
| Rootkit | `references/rootkit.md` |
| Fileless | `references/fileless.md` |
| Keylogger | `references/keylogger.md` |
| Botnet | `references/botnet.md` |

## 🛠️ Contribuição

Veja `CONTRIBUTING.md` para contribuir com novas famílias ou melhorias.

## 📄 Licença

CC-BY-4.0 — Atribuição necessária.

## Créditos e fontes

### anbeime/skill (upstream)
- Repositório upstream: https://github.com/anbeime/skill
- Licença do upstream: **CC-BY-4.0** (Creative Commons Attribution 4.0 International), conforme o badge do próprio repositório.
- O que veio dele: a estrutura de skills (`skills/<nome>/<nome>/SKILL.md`), o modelo `SKILL.md`, o `report-template.md` e a organização de referências de famílias de malware.

### Contribuição original — Badwolfgang154
- Ferramentas: `tools/ioc_extractor.py`, `tools/skill_validator.py`, `tools/threatfox_client.py`.
- Testes: `tests/test_ioc_extractor.py`, `tests/test_threatfox_client.py`.
- Documentação e descrição do projeto: `README.md`, `README_EN.md`, `USAGE-GUIDE.md`, `API_INTEGRATION.md`, `QUICKSTART.md`, `CONTRIBUTING.md`, `DEPLOYMENT.md`, `DEPLOYMENT_GUIDE.md`, `DEPLOYMENT_CHECKLIST.md`, `SUMMARY.md`, `PROJECT_SUMMARY.md`, `FINAL-SUMMARY.md`, `DEMO-SUCCESS.md`, `README_EN_translated.md`.
- Esses arquivos não constam no upstream `anbeime/skill`; foram adicionados ou personalizados por Badwolfgang154.

### MITRE ATT&CK
- Base do mapeamento de técnicas: https://attack.mitre.org
- As famílias mapeiam comportamentos para técnicas como T1547.001, T1204.002, T1036, T1027, etc.

### ThreatFox / abuse.ch
- API pública de indicadores de comprometimento (IOCs): https://threatfox.abuse.ch
- O cliente `tools/threatfox_client.py` consome a API somente para leitura.

### Licença
- O projeto usa **CC-BY-4.0**.
- O upstream `anbeime/skill` **indica a licença CC-BY-4.0 em seu README** (não há arquivo LICENSE no repositório).
- São licenças permissivas e compatíveis; não há conflito.

