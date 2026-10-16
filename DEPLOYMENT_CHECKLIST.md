# Checklist de Implantação

## ✅ Pré-requisitos

- [ ] Git instalado
- [ ] Python 3.8+ disponível
- [ ] Acesso de rede para repositório

## 📦 Download

- [ ] Repositório clonado:
  ```bash
  git clone https://github.com/anbeime-cybersecurity-skills.git
  ```

## 📂 Estrutura

- [ ] `skills/cyber-threat-spectrum/cyber-threat-spectrum/SKILL.md` existe
- [ ] `skills/cyber-threat-spectrum/cyber-threat-spectrum/references/` contém 10 famílias
- [ ] `SKILL_SOURCES.json` registra a habilidade

## 🛠️ Validação

```bash
python tools/skill_validator.py validate skills/cyber-threat-spectrum
```

## 📊 Estatísticas

- [ ] `README.md` com estatísticas atuais (se atualizar)
- [ ] `SKILL_SOURCES.json` com métricas atualizadas

## 🔄 Automação

- [ ] Tarefa agendada criada (Windows)
- [ ] Script batch configurado (Windows)
- [ ] Cron/Daemon configurado (Linux)

## 📈 Monitoramento

- [ ] Métrica de detecção configurada
- [ ] Alertas disparados em múltiplas ocorrências
- [ ] Relatórios gerados com `report-template.md`

## 🧹 Manutenção

- [ ] Cargo de limpeza do cache executado
- [ ] Registro de SKILL_SOURCES check-out
- [ ] Documentação de configuração atualizada
