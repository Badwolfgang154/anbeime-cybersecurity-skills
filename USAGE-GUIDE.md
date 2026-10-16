# Guia de Uso

## ✅ Habilidade Cyber Threat Spectrum Analysis

Habilidade completa para classificação e análise do espectro de ameaças
cibernéticas, com foco em mapeamento MITRE ATT&CK, assinaturas de detecção
e mitigação defensiva.

## 📋 Estrutura da Habilidade

```
skills/cyber-threat-spectrum/cyber-threat-spectrum/
├── SKILL.md                        ← Definição principal
├── references/
│   ├── virus.md                    ← Vírus
│   ├── worm.md                     ← Verme
│   ├── trojan-rat.md               ← Trojan / RAT
│   ├── ransomware.md               ← Ransomware
│   ├── spyware.md                  ← Spyware
│   ├── adware.md                   ← Adware
│   ├── rootkit.md                  ← Rootkit
│   ├── fileless.md                 ← Fileless
│   ├── keylogger.md                ← Keylogger
│   └── botnet.md                   ← Botnet
└── assets/                         ← Recursos (opcional)
```

## 🚀 Como Usar

### 1. Instalar

```bash
git clone https://github.com/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
```

### 2. Ler a habilidade principal

```bash
cat SKILL.md
```

### 3. Escolher a família de ameaça

```bash
ls references/
# virus.md, worm.md, trojan-rat.md, ransomware.md, ...
```

### 4. Seguir o guia de detecção

Cada arquivo `references/*.md` contém:
- **Comportamento** — mecânica da ameaça
- **Mapeamento ATT&CK** — técnicas relevantes
- **Assinatura de detecção** — indicadores por categoria
- **Mitigação** — resposta

## 📖 Relatórios

Use `references/report-template.md` para produzir relatórios de análise:

```bash
cat references/report-template.md
```

## 🔌 Como Integrar

- **SIEM**: extraia os IOCs (hashes, IPs, domínios) e importe como regras
- **EDR**: use os grupos de detecção para sensors de comportamento
- **Correlação**: combine técnicas ATT&CK para rastrear cadeias de ataque
- **Treino**: use a estrutura de relatório para categorizar incidentes

## ⚙️ Dependências

- Python 3.8+ (para validação opcional)
- Git (para instalação)

## ⚖️ Limitações

Esta habilidade trata de classificação defensora e mapeamento de ameaças.
Não inclui códigos operacionais de exploração, payloads, ou métodos de
bypass de detecção. Foco em análise, detecção e mitigação.

## 🤝 Contribuição

Para contribuir:
1. Clone o repositório
2. Adicione uma família em `references/`
3. Atualize o `SKILL_SOURCES.json`
4. Envie um PR com `feat: add <family>`
