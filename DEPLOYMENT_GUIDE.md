# Deploying

Guia completo para implantar a habilidade **Cyber Threat Spectrum Analysis**.

## 📋 Pré-requisitos

- Git
- Python 3.8+ (para validação)
- Cliente API de monitoramento (opcional)

## 🏗️ Deploy

### Método 1: Git

```bash
git clone https://github.com/anbeime-cybersecurity-skills.git
cd anbeime-cybersecurity-skills/skills/cyber-threat-spectrum/cyber-threat-spectrum
```

### Método 2: Skills Store

```bash
# Usando o script de sincronização
python tools/sync.py --source https://github.com/anbeime-cybersecurity-skills.git
```

## 🔧 Configuração

### 1. Ambiente

```bash
python -m venv venv
source venv/bin/activate
pip install -r tools/requirements.txt
```

### 2. Variáveis de Ambiente

```bash
export SKILL_STORE_API_URL="https://sua-api.com/api/skills"
export SKILL_STORE_API_KEY="sua-chave"
```

### 3. Habilidade Principal

```bash
# Ativar
jupyter skill enable cyber-threat-spectrum

# Verificar
jupyter skill status cyber-threat-spectrum
```

## 📊 Monitoramento

### Métricas

- Taxa de detecção por família
- Tempo de resposta
- Falso positivo
- Cobertura de técnicas ATT&CK

### Alertas

- Multiplas ocorrências de same hash
- Padrões de beaconing
- Tentativas de criptografia

## 🔄 Atualização

```bash
# Sincronizar
python tools/sync.py --update --daemon

# Verificar atualizações
python tools/sync.py --list-updates
```

## 🧹 Manutenção

```bash
# Limpar cache
rm -rf .cache/*

# Validar
python tools/skill_validator.py validate skills/cyber-threat-spectrum
```
