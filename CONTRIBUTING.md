# Contribuição

Obrigado pelo interesse neste repositório de habilidades de segurança cibernética.

## Fluxo de Contribuição

1. **Copiar o template** — clone a estrutura de uma habilidade existente
2. **Editar SKILL.md** — substitua todos os placeholders pelos conteúdos reais
3. **Validar** — rode `python tools/skill_validator.py validate`
4. **Enviar PR** — descreva o uso e os cenários da habilidade

## Convenção de Nomes

- Nome da habilidade: minúsculas + hífens (ex: `cyber-threat-spectrum-analysis`)
- Diretório: o mesmo nome da habilidade
- Tags: minúsculas, sem espaços

## Estrutura de Diretórios

Adote a estrutura dupla aninhada:

```
skills/
└── your-skill/
    └── your-skill/
        ├── SKILL.md          ← core (obrigatório)
        ├── assets/           ← imagens/ recursos (opcional)
        └── references/       ← documentação de apoio (opcional)
```

## Requisitos do SKILL.md

- Deve começar com YAML frontmatter (`---`)
- Campos `name` e `description` são obrigatórios
- Corpo com no mínimo 10 linhas e um `#` heading
- Recomenda-se: objetivo, uso, lógica central, notas, exemplos

## Ferramentas

Coloque o código das ferramentas na pasta `tools/`.
- Cada ferramenta tem seu próprio `README.md`
- Mantenha compatibilidade com Python 3.8+

## Documentação

Coloque a documentação em `docs/` em Markdown:
- `specification.md` — especificação
- `best-practices.md` — boas práticas
- `quickstart.md` — início rápido

## Checklist de PR

- [ ] Roda `python tools/skill_validator.py validate` sem erros
- [ ] Nome da habilidade minúsculo, separado por hífens
- [ ] `SKILL.md` com frontmatter YAML completo
- [ ] Corpo contém pelo menos um exemplo
- [ ] Não modificou arquivos não relacionados
- [ ] Mensagem de commit clara (ex: `feat: add cyber-threat-spectrum-analysis`)

## Padrões de Commit

| Prefixo | Uso | Exemplo |
|---|---|---|
| `feat:` | Nova habilidade | `feat: add cyber-threat-spectrum-analysis` |
| `fix:` | Correção | `fix: correct yaml parsing in validator` |
| `docs:` | Documentação | `docs: update quickstart guide` |
| `chore:` | Manutenção | `chore: update dependencies` |
| `refactor:` | Refatoração | `refactor: restructure references` |
