# Hands-On — Cyber Threat Spectrum Analysis

## Objetivo

Aplicar a habilidade **Cyber Threat Spectrum Analysis** para classificar uma
ameaça simulada, produzir um relatório e verificar a cobertura de detecção.

## Configuração

### 1. Instalar o repositório

```bash
git clone https://github.com/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
```

### 2. Verificar a estrutura

```bash
ls -R
```

Você deverá ver:
- `SKILL.md` — definição da skill
- `references/` — 10 famílias de malware com guias de detecção

---

## Exercício 1 — Classificar uma Ameaça

### Cenário

Você recebe um alerta de um host com:
- Arquivos com extensão inesperada (`.locked`, `.encrypted`)
- Múltiplas alterações no sistema de backup (shadow copies deletados)
- Processo suspeito rodando na sequência (`vssadmin delete shadows`, `wbadmin delete`, `cipher /w`)
- Arquivos criptografados espalhados em unidades compartilhadas

### Passo a passo

1. **Identificar a família** — Cite 3 indicadores que apontam para Ransomware.
2. **Mapear a família** — Procure `references/ransomware.md`.
3. **Extrair técnicas ATT&CK** — Liste pelo menos 3 técnicas relevantes.
4. **Definir IOCs** — Escreva 3 indicadores de comprometimento.
5. **Produzir resposta** — Liste ações de contenção, erradicação e recuperação.

### Resposta Esperada

1. **Família**: Ransomware
   - Indicadores: arquivos renomeados com extensões novas; shadow copies deletados; sequência de comandos de parada de backup.
2. **Referência**: `references/ransomware.md`
3. **Técnicas ATT&CK**:
   - `T1486` Data Encrypted for Impact
   - `T1489` Service Stop
   - `T1070.004` Indicator Removal: Timestamps
4. **IOCs**:
   - Arquivos com novas extensões (`.locked`, `.encrypted`)
   - Comando `vssadmin delete shadows`
   - Arquivos de nota de resgate `.html` ou `.txt`
5. **Resposta**:
   - **Contenção**: isolar o host; bloquear tráfego de saída para C2
   - **Erradicação**: restaurar de backup offline; remover malware; verificar persistência
   - **Recuperação**: restaurar arquivos dos backups; validar integridade; reforçar permissões

---

## Exercício 2 — Mapear uma Cadeia de Ataque

### Cenário

Um incidente mostrou:
- Acesso via Remote Desktop Protocol (RDP) de um IP externo
- Execução de PowerShell com script obfuscado
- Injeção de código em um processo legítimo
- Cochilos de credenciais em um banco de dados

### Passo a passo

1. **Monte a cadeia**: ordene os eventos (inicial, lateral, execução, exfiltração)
2. **Mapeie cada etapa** a uma técnica ATT&CK
3. **Cite a referência** que melhor cobre a etapa

### Resposta Esperada

| Etapa | Técnica ATT&CK | Referência |
|---|---|---|
| Acesso RDP externo | `T1021.001` Remote Desktop Protocol | `trojan-rat.md` / `worm.md` |
| PowerShell obfuscado | `T1059.001` PowerShell | `fileless.md` |
| Injeção de código | `T1055` Process Injection | `fileless.md` |
| Exfiltração de credenciais | `T1003` Credential Dumping | `spyware.md` / `trojan-rat.md` |

---

## Exercício 3 — Produção de Relatório

### Instruções

1. Copie `references/report-template.md`
2. Preencha com dados de uma ameaça real ou simulada
3. Use os campos: Summary, Methodology, Evidence, ATT&CK Mapping, IOCs, Response

### Entregáveis

- Relatório preenchido
- Pelo menos 4 IOC (arquivo, rede, sistema, log)
- Pelo menos 2 técnicas ATT&CK

---

## Dicas de Ouro

- **Comece sempre com `SKILL.md`** — ele reúne a visão geral e fluxos de uso.
- **Cada família segue o mesmo modelo**: Behavior → ATT&CK → Detection → Mitigation.
- **IOCs devem ser reutilizáveis**: hashes, IPs, domínios, paths.
- **Documente tudo**: use o `report-template.md` para consistência.

## Próximos Passos

1. Adicione uma nova família (ex: `downlogger`) seguindo o mesmo padrão.
2. Atualize `SKILL_SOURCES.json` com a nova habilidade.
3. Envie um PR seguindo `CONTRIBUTING.md`.
