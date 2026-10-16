# 🚀 Implementação

Guia de implantação completo para a habilidade **Cyber Threat Spectrum Analysis**.

## 📋 Pré-requisitos

- Git
- Python 3.8+ (para validação)
- Node.js (opcional, para scripts JS)
- Acesso a ambientes de monitoramento (EDR/SIEM)

## 🏗️ Deploy

### Método 1: Contêiner (Docker)

```bash
docker build -t cyber-threat-skills .
docker run -d --name cyber-threat-skills cyber-threat-skills
```

### Método 2: Instalar via Git

```bash
git clone https://github.com/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
```

### Método 3: Importar via SKILL_SOURCES.json

```json
{
  "sources": {
    "cyber-threat-spectrum-analysis/cyber-threat-spectrum-analysis": {
      "upstream_source": "local-repository",
      "discovered_at": "2026-10-16T14:30:00.000000",
      "description": "Framework for classifying and analyzing the full spectrum of cybersecurity threats."
    }
  }
}
```

Importar no gerenciador de skills.

## 📜 Post-Instalação

### 1. Ativar a habilidade

```bash
openclaw skill enable cyber-threat-spectrum
```

### 2. Verificar

```bash
openclaw skill status cyber-threat-spectrum
```

### 3. Testar

```bash
# Levantar uma ameaça simulada
python tools/attack_simulator.py --family ransomware

# Verificar a detecção
python tools/detection_checker.py --family ransomware
```

## 🔍 Monitoramento

### Métricas

- Taxa de detecção por família
- Tempo de resposta
- Falso positivo
- Cobertura de técnicas ATT&CK

### Alertas

Configurar alertas para:
- Múltiplos hosts com o mesmo binário
- Padrões de beaconing
- Tentativas de criptografia

## 📈 Escalabilidade

Para escalonar:

1. Centralizar `SKILL_SOURCES.json` em um repositório
2. Publicar `skills/` via CDN
3. Autenticar agentes com tokens
4. Sincronizar a cada N horas via CLI

```bash
# Sincronizar via CLI
python tools/sync.py --source remote://skills --dest local://skills --hours 24
```

## 🧹 Manutenção

```bash
# Verificar validação
python tools/skill_validator.py validate skills/cyber-threat-spectrum

# Limpar cache
rm -rf .cache/*

# Atualizar SKILL_SOURCES.json
python tools/sync.py --update-registry
```

## 🛡️ Segurança

- Verificar assinatura dos bins externos
- Renovar tokens API periodicamente
- Audit.log para acesso às habilidades
- Envolver acesso a diagnósticos
