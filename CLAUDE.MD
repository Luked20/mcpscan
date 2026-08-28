# CLAUDE.md

Este arquivo orienta o Claude (e qualquer outro assistente/dev) ao trabalhar neste repositório.

## O que é este projeto

Um scanner de segurança self-serve para **MCP servers e agent skills** — pensa em "Snyk, mas para MCP". Roda localmente e no CI, detecta vulnerabilidades conhecidas de MCP/agent-skills antes do deploy, e devolve um relatório acionável (ideal: exit code não-zero + anotação no PR).

Não é uma plataforma enterprise de governança de agentes. É uma ferramenta de linha de comando que um dev instala via `npm install` (ou `npx`) e usa em 5 minutos, sem falar com ninguém.

## Por que isso existe (contexto de mercado — não apagar, guia decisões de escopo)

- A Snyk auditou 3.984 agent skills e achou pelo menos uma falha de segurança em **36,82%** delas.
- Já existem casos documentados de leitura arbitrária de arquivo, RCE e tool poisoning em MCP servers oficiais amplamente usados.
- A OWASP formalizou um **MCP Top 10**: tool poisoning, schema poisoning, tool shadowing, shadow servers, entre outros.
- A camada enterprise (governança, observabilidade, gateway) já está disputada: TrueFoundry, Noma, Lunar.dev, Portkey, Snowflake, Microsoft Entra Agent ID, AWS Bedrock AgentCore. **Não competir aí.**
- O espaço vazio é a camada de baixo: scanner self-serve para dev individual e time pequeno.

**Implicação prática:** toda decisão de produto deve favorecer "um dev sozinho instala e usa em minutos" sobre "recurso enterprise completo". Se uma feature exige onboarding, SSO, dashboard multi-tenant ou conversa com SDR, provavelmente é a feature errada nesta fase.

## Público e modelo de distribuição

- **Comprador:** desenvolvedor individual ou tech lead de time pequeno que escreve/mantém MCP servers ou agent skills.
- **Canal:** GitHub (repo público, boa documentação, badges de "scanned by X") e npm (`npx mcp-scan` ou similar).
- **Venda:** bottom-up, product-led, sem SDR, sem call de vendas. Adoção começa pelo CLI/CI, monetização (se houver) vem depois via freemium ou GitHub Action paga.
- **Distribuição prioritária:** GitHub Action pronta para colar no workflow + pacote npm instalável localmente.

## Escopo do MVP

O scanner deve, no mínimo:

1. **Analisar MCP servers** (definições de tools, schemas JSON, prompts/descriptions expostos) em busca de:
   - Tool poisoning (descrições de tool que escondem instruções maliciosas)
   - Schema poisoning (schemas que abrem excesso de superfície — ex. paths arbitrários, comandos shell)
   - Tool shadowing (tool com nome/assinatura que sobrepõe/mascara outra)
   - Shadow servers (server não declarado/inesperado respondendo por um nome esperado)
   - Padrões de leitura arbitrária de arquivo e RCE (ex. tools que aceitam paths não sanitizados, `eval`, `exec`, `child_process` sem allowlist)
2. **Analisar agent skills** (arquivos SKILL.md e recursos associados) em busca de:
   - Instruções ocultas/prompt injection embutidas na descrição do skill
   - Permissões implícitas excessivas (rede, filesystem, exec) não declaradas
   - Dependências de terceiros não auditadas referenciadas pelo skill
3. **Rodar em dois modos:**
   - CLI local (`mcp-scan ./meu-server`) — feedback humano, cores, severidade
   - CI (`mcp-scan --ci`) — saída em JSON/SARIF, exit code não-zero em achados críticos, compatível com anotação de PR no GitHub Actions
4. **Relatório com:**
   - Severidade (crítico/alto/médio/baixo) mapeada ao OWASP MCP Top 10 quando aplicável
   - Localização exata (arquivo, linha, campo do schema)
   - Explicação curta do risco + sugestão de correção

Fora de escopo por enquanto: dashboard web, multi-tenant, SSO/RBAC, telemetria centralizada, gateway de runtime. Isso é a camada enterprise — não é o produto.

## Arquitetura (proposta — ajustar conforme decisões reais do projeto)

- **Linguagem:** TypeScript/Node.js — alinhado com distribuição via npm/npx e integração natural com GitHub Actions.
- **Estrutura sugerida:**
  ```
  /src
    /rules        # cada regra de detecção como módulo isolado e testável
    /parsers      # parsers de manifest MCP (tool schemas) e SKILL.md
    /report       # formatação de saída (texto, JSON, SARIF)
    /cli          # entrypoint do CLI
  /tests
    /fixtures     # exemplos de MCP servers/skills vulneráveis e limpos, usados nos testes de regra
  ```
- **Regras como plugins:** cada vulnerabilidade do OWASP MCP Top 10 deve ser uma regra independente, com testes próprios usando fixtures reais (idealmente baseadas nos casos documentados pela Snyk/OWASP), para permitir adicionar novas regras sem tocar no core.
- **Saída SARIF é prioridade** desde cedo — é o que faz a ferramenta plugar direto em GitHub code scanning sem esforço do usuário.

## Convenções de código

- Preferir funções puras e regras testáveis isoladamente (input: definição de tool/skill parseada → output: lista de findings).
- Nunca fazer uma regra "ampla demais" que gera falso positivo alto — isso mata confiança em ferramenta de segurança self-serve mais rápido que qualquer outra coisa. Prefira regra específica e documentada sobre heurística genérica.
- Toda regra nova precisa de pelo menos um fixture positivo (detecta) e um negativo (não detecta em código limpo) nos testes.
- Mensagens de erro/finding devem ser acionáveis: dizer o que corrigir, não só o que está errado.

## Como testar

```bash
npm install
npm test          # roda testes de regra contra fixtures
npm run scan -- ./tests/fixtures/exemplo-vulneravel
```

## Notas para o Claude ao trabalhar aqui

- Este é um projeto pessoal em estágio inicial — priorize simplicidade e velocidade de shipping sobre arquitetura "enterprise-ready".
- Ao propor novas regras de detecção, ancorar sempre no OWASP MCP Top 10 e/ou em casos reais documentados (Snyk, CVEs de MCP servers conhecidos) — evitar inventar categorias de risco sem base.
- Ao propor features, perguntar sempre: "isso ajuda um dev sozinho a rodar `npx mcp-scan` e confiar no resultado em 2 minutos?" Se a resposta for não, provavelmente é escopo futuro, não agora.
- Documentação (README, mensagens de CLI) deve ser voltada a dev, direta, sem jargão de compliance/enterprise.

---
*Este arquivo é um rascunho inicial gerado a partir da descrição do projeto — ajuste as seções de arquitetura e stack conforme decisões reais forem tomadas.*