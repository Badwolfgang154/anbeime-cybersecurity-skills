# Integração de API

Guia para integrar a habilidade **Cyber Threat Spectrum Analysis** com uma API.

## 📋 Configuração

### 1. Arquivo de Configuração

Edite `config.py`:

```python
# URL da API
SKILL_STORE_API_URL = "https://sua-api.com/api/skills"

# Chave de acesso
SKILL_STORE_API_KEY = "sua-chave"

# Intervalo de sincronização (horas)
SYNC_INTERVAL_HOURS = 24
```

### 2. Variáveis de Ambiente

```bash
export SKILL_STORE_API_URL="https://sua-api.com/api/skills"
export SKILL_STORE_API_KEY="sua-chave"
```

## 🔌 Endpoints

### GET /api/skills
Retorna a lista de habilidades disponíveis.

```bash
curl -X GET "https://api.example.com/api/skills" \
  -H "Authorization: Bearer $SKILL_STORE_API_KEY"
```

### POST /api/skills/sync
Sincroniza a lista de habilidades.

```bash
curl -X POST "https://api.example.com/api/skills/sync" \
  -H "Authorization: Bearer $SKILL_STORE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sync_type": "full"}'
```

### GET /api/skills/{name}
Retorna detalhes de uma habilidade específica.

```bash
curl -X GET "https://api.example.com/api/skills/cyber-threat-spectrum" \
  -H "Authorization: Bearer $SKILL_STORE_API_KEY"
```

## 🔄 Fluxo de Sincronização

```text
1. Configurar SKILL_STORE_API_URL e SKILL_STORE_API_KEY
2. Ativar sync via CLI
3. Testar conexão (GET /api/skills)
4. Executar sync --once
5. Verificar resultados (logs, stats)
```

## 📊 Exemplo de Resposta

```json
{
  "status": "success",
  "skills": [
    {
      "name": "cyber-threat-spectrum-analysis",
      "version": "1.0.0",
      "author": "upstage/solar-mini4",
      "updated_at": "2026-10-16T14:30:00Z",
      "references_count": 10
    }
  ]
}
```

## 🔍 Troubleshooting

| Erro | Solução |
|---|---|
| 401 | Verificar `SKILL_STORE_API_KEY` |
| 404 | Confirmar `SKILL_STORE_API_URL` |
| Timeout | Verificar conectividade rede |
| Parse erro | Validar JSON da resposta |
