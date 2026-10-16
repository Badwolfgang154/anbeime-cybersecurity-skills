# Guia de Início Rápido

## 🚀 5-Minutos para Instalar

### 1. Instalar as dependências

```bash
cd anbeime-cybersecurity-skills
pip install -r tools/requirements.txt 2>/dev/null || echo "Validação opcional"
```

### 2. Executar uma vez

```bash
python tools/main.py --once
```

Isso fará:
- Explorar as habilidades do GitHub (incluindo esta)
- Salvar em `data/skills.json`
- Gerar logs em `logs/updater.log`

### 3. Ver o resultado

```bash
python tools/main.py --stats
python tools/main.py --export skills.csv
```

## 📋 Funcionalidades

### Uso Básico

```bash
# Uma atualização
python tools/main.py --once

# Rodar em segundo plano (atualização automática a cada 24h)
python tools/main.py --daemon

# Ver estatísticas
python tools/main.py --stats

# Exportar CSV
python tools/main.py --export output.csv

# Logs detalhados
python tools/main.py --once -v
```

### Sincronização via API

```bash
# 1. Configurar API
# Edite config.py:
#   SKILL_STORE_API_URL = "https://seu-api.com/api/skills"
#   SKILL_STORE_API_KEY = "***"

# 2. Ativar sincronização
python tools/main.py --once --api-sync

# 3. Teste da API (opcional)
pip install flask flask-cors
python tools/api_server_example.py
```

## 🤖 Pipeline da Atualização

```
GitHub (clone) → 182+ skills → data/skills.json → logs/updater.log
```

### Estrutura do Repositório

```
anbeime-cybersecurity-skills/
├── SKILL_SOURCES.json          ← Registro de skills
├── README.md                   ← Documentação principal
├── docs/                       ← Especificação, práticas, início rápido
├── tools/                      ← Validação e sincronização
├── skills/
│   └── cyber-threat-spectrum/
│       ├── SKILL.md            ← Habilidade principal
│       └── references/         ← 10 famílias
└── assets/                     ← Recursos (opcional)
```

## 🔄 Automação

### Tarefa Agendada (Windows)

Use o `setup_scheduled_task.ps1`:

```powershell
.\setup_scheduled_task.ps1
```

Ativa a tarefa a cada dia às 02:00.

### Script Batch

Duplo clique em `run_once.bat`:

```batch
python tools/main.py --once
```

## 🔍 Verificar

```bash
# Ver ports usados
ss -tlnp | grep :8080

# Ver processos
ps aux | grep python
```
