# Como este projeto é organizado

Um mapa prático do repositório: o que cada pasta faz, o que cada arquivo é, e
como as peças se ligam.

Este documento é o "onde fica o quê". O **porquê** de cada decisão está em
[`SPEC.md`](SPEC.md), e o detalhe de cada regra está em
[`docs/rules/`](rules/README.md). Aqui a linguagem é direta de propósito.

---

## 1. O que a ferramenta faz

`mcpscan` é um scanner de segurança de linha de comando. Você aponta para uma
pasta, ele procura três tipos de arquivo — manifestos de MCP server, configs de
cliente MCP e arquivos `SKILL.md` — e diz o que tem de errado neles.

Roda em dois modos: no seu terminal (saída colorida) e no CI (saída JSON ou
SARIF, com código de saída não-zero quando acha algo grave).

---

## 2. O caminho de um scan, do começo ao fim

Esse é o fluxo inteiro. Tudo no projeto é uma dessas cinco etapas:

```
 arquivos no disco
        │
        ▼
  ┌───────────┐   lê e traduz cada arquivo para uma estrutura
  │  COLETAR  │   ── src/collect/
  └───────────┘
        │  ScanTarget  (tools, servers, skills, sourceFiles, suppressions)
        ▼
  ┌───────────┐   roda as 14 regras sobre essa estrutura
  │  ANALISAR │   ── src/rules/ + src/core/engine.ts
  └───────────┘
        │  Finding[]
        ▼
  ┌───────────┐   remove o que foi suprimido ou está no baseline
  │  FILTRAR  │   ── src/core/suppress.ts + src/report/baseline.ts
  └───────────┘
        │  Finding[]  (+ contadores do que saiu)
        ▼
  ┌───────────┐   escolhe o código de saída: 0, 1 ou 2
  │  DECIDIR  │   ── src/scan.ts
  └───────────┘
        │
        ▼
  ┌───────────┐   pretty, json, sarif, github ou baseline
  │ FORMATAR  │   ── src/report/
  └───────────┘
        │
        ▼
    stdout ou arquivo
```

### O mesmo em passos, quando você roda `mcpscan .`

1. **`src/cli/index.ts`** lê as flags, carrega o `mcpscan.config.json` se
   existir, decide quem ganha (flag > config > padrão) e carrega o baseline.
2. **`src/scan.ts`** assume dali. Valida a seleção de regras, confere que o
   caminho existe.
3. **`src/collect/index.ts`** varre a pasta e manda cada arquivo para o coletor
   certo. Devolve um `ScanTarget` — o "estado do mundo" numa estrutura só.
4. **`src/core/engine.ts`** roda cada regra sobre os sujeitos que ela pede e
   junta os achados.
5. **`src/core/suppress.ts`** tira os achados que têm comentário de supressão
   válido; o baseline tira os já registrados.
6. **`src/scan.ts`** decide o código de saída comparando a severidade dos
   achados restantes com `--fail-on`.
7. **`src/report/`** transforma a lista em texto.

---

## 3. A árvore

```
mcpscan/
├── src/            o código da ferramenta
│   ├── cli/        entrada do executável
│   ├── collect/    lê arquivos → estrutura
│   ├── core/       tipos, motor de regras, utilidades
│   ├── rules/      as 14 regras de detecção
│   ├── report/     estrutura → texto
│   ├── scan.ts     orquestra tudo
│   └── config.ts   lê o mcpscan.config.json
├── tests/          testes + dados de teste
│   ├── fixtures/   exemplos que escrevemos
│   └── corpus/     código real de terceiros
├── docs/           documentação
│   └── rules/      uma página por regra
├── scripts/        ferramentas de manutenção
└── .github/        CI e exemplo de workflow
```

---

## 4. `/src` — o código

### `/src/collect` — ler arquivos

Todo arquivo do projeto aqui segue a mesma regra: **recebe texto, devolve
estrutura, nunca lê disco e nunca lança exceção.** Isso os torna triviais de
testar — você passa uma string e confere a saída.

| Arquivo | O que faz |
|---|---|
| `index.ts` | O varredor. Acha os arquivos e manda cada um para o coletor certo. É o único que toca o disco. |
| `mcp-manifest.ts` | Lê um JSON com uma lista `tools` → `ToolDefinition[]` |
| `mcp-config.ts` | Lê `.mcp.json` / `claude_desktop_config.json` → `ServerDefinition[]` |
| `skill-md.ts` | Lê um `SKILL.md` (frontmatter YAML + corpo) → `SkillDefinition` |
| `source.ts` | Lê `.ts`/`.js`/`.py` → `SourceFile` (só classifica a linguagem e guarda o texto) |
| `suppression.ts` | Acha os comentários `mcpscan-disable-next-line` em qualquer arquivo |

**Como o `index.ts` decide o destino de cada arquivo:**

```
arquivo chamado SKILL.md?          → skill-md.ts
extensão .ts/.js/.py/…?            → source.ts   (mas pula arquivos de teste)
qualquer outro .json               → mcp-manifest.ts
  e se o nome for .mcp.json,
  mcp.json ou claude_desktop_       → mcp-config.ts também
  config.json
```

Em **todos** os casos ele também roda o `suppression.ts`, porque um comentário
de supressão pode aparecer em qualquer tipo de arquivo.

Dois detalhes que economizam confusão depois:

- Um arquivo cujo **nome declara o que ele é** (`SKILL.md`, `.mcp.json`) e que
  não abre vira erro de scan (código 2), não silêncio. Já um `.json` qualquer
  que não é manifesto é ignorado sem barulho — ele nunca alegou ser nada.
- Arquivos de teste (`tests/`, `spec/`, `__tests__/`, `*.test.ts`) são pulados
  antes de virarem `SourceFile`. Código de teste não roda na frente de um
  agente.

### `/src/core` — o miolo

| Arquivo | O que faz |
|---|---|
| `types.ts` | **O arquivo mais importante do projeto.** Define `ToolDefinition`, `ServerDefinition`, `SkillDefinition`, `SourceFile`, `Finding`, `Rule`, `ScanTarget`. Tudo passa por aqui. |
| `engine.ts` | Roda as regras. Entrega a cada uma os sujeitos do tipo que ela pediu, junta os achados, ordena. |
| `severity.ts` | Ordem das severidades e comparações (`critical` > `high` > …). |
| `location.ts` | Converte deslocamento em texto para linha e coluna. É o que faz `tools.json:14:32` ser clicável. Também formata o caminho JSON exibido no achado. |
| `suppress.ts` | Aplica as supressões e reporta as que não funcionaram. |
| `fingerprint.ts` | A identidade estável de um achado. Usada pelo SARIF e pelo baseline. |

### `/src/rules` — as 14 regras

Uma regra é um objeto com metadados (`id`, `title`, `severity`, `confidence`,
`owasp`) e uma função `check()`. Nada mais.

O campo **`appliesTo`** diz o que a regra quer receber:

| `appliesTo` | A regra recebe | Regras |
|---|---|---|
| `tool` | uma tool por vez | MCP001, MCP002, MCP003, MCP005 |
| `server` | uma entrada de config por vez | MCP007, MCP009 |
| `skill` | um `SKILL.md` por vez | SKILL001–SKILL004 |
| `sourceFile` | um arquivo de código por vez | MCP008, MCP010 |
| `target` | **o scan inteiro** | MCP004, MCP006 |

`target` existe porque algumas perguntas só fazem sentido olhando tudo: "essa
tool tem o mesmo nome que outra?" não dá para responder olhando uma tool só.

**Catálogo completo:**

| ID | O que detecta | Severidade |
|---|---|---|
| MCP001 | Instrução para o modelo escondida na descrição da tool | critical |
| MCP002 | Caractere Unicode invisível na definição da tool | critical |
| MCP003 | Instrução para o modelo dentro do `inputSchema` | critical |
| MCP004 | Parâmetro de caminho sem restrição numa tool de arquivo | high |
| MCP005 | Parâmetro de comando sem restrição | high |
| MCP006 | Tool que sobrepõe ou dá ordens sobre outra | high |
| MCP007 | Servidor iniciado sem versão fixada | medium |
| MCP008 | `eval`, `exec` e afins no código do servidor (TypeScript/JavaScript) | high |
| MCP009 | Credencial escrita direto no config | high |
| MCP010 | `eval`, `exec`, shell e desserialização insegura em código Python | high |
| SKILL001 | Instrução escondida no corpo da skill | critical |
| SKILL002 | Instrução para o modelo na `description` da skill | critical |
| SKILL003 | Skill usa capacidade que não declarou | high |
| SKILL004 | Skill baixa e executa código remoto | high |

`/src/rules/shared/` tem o que mais de uma regra usa:

- `patterns.ts` — detector de injeção de prompt. Usado por MCP001, MCP003 e
  SKILL002.
- `invisible.ts` — política de caracteres invisíveis. Usado por MCP002 e
  SKILL001.
- `schema-walk.ts` — percorre um JSON Schema recursivamente.

`/src/rules/index.ts` é só a lista `RULES`. **Adicionar uma regra ali é o que a
coloca no ar** — o resto do sistema descobre tudo a partir dessa lista.

### `/src/report` — transformar achados em texto

| Arquivo | Saída |
|---|---|
| `pretty.ts` | Texto colorido para humano no terminal |
| `sarif.ts` | SARIF 2.1.0, o formato que o GitHub Code Scanning lê |
| `github.ts` | Comandos `::error` que viram anotação no PR |
| `baseline.ts` | Arquivo de baseline (gerar e ler) |
| `format.ts` | Só valida o nome do formato pedido |

O formato `json` não tem arquivo próprio — é montado direto no
`cli/index.ts`, porque é literalmente `JSON.stringify` do resultado.

### Os dois arquivos soltos em `/src`

- **`scan.ts`** — a função `scan()`, que é a ferramenta inteira sem a CLI.
  Recebe opções, devolve `{ findings, exitCode, stats }`. Quase todo teste
  chama isto, não a CLI.
- **`config.ts`** — lê e valida o `mcpscan.config.json`, e a função
  `resolveOptions()` que decide flag vs. config vs. padrão.

---

## 5. `/tests`

Duas coisas bem diferentes convivem aqui: os **testes** e os **dados** que eles
usam.

### Os testes

Espelham a estrutura do `src/`: `tests/collect/` testa `src/collect/`,
`tests/rules/MCP004.test.ts` testa `src/rules/mcp/MCP004.ts`, e assim por
diante.

A exceção é **`tests/anti-fp.test.ts`**, que não testa um arquivo — testa o
projeto. Ele verifica, para toda regra registrada, que:

- existe fixture vulnerável e fixture limpo;
- existe documentação em `docs/rules/<ID>.md`;
- a severidade respeita o teto da confiança declarada;
- a regra acha algo no próprio fixture vulnerável;
- **nenhuma regra dispara no fixture limpo de nenhuma outra regra**;
- o corpus real não produz nenhum achado `high`/`critical`.

Ele descobre tudo pelo sistema de arquivos, então uma regra nova é coberta
assim que os fixtures dela existem, sem editar este arquivo.

### `/tests/fixtures` — exemplos que nós escrevemos

Duas famílias:

**Por regra** — `MCP001/`, `SKILL003/` etc. Cada uma com `vulnerable/` (a regra
tem que achar) e `clean/` (nenhuma regra pode achar nada).

**Por coletor** — usados pelos testes de `src/collect/`, sem par
vulnerável/limpo:

| Pasta | Para que serve |
|---|---|
| `manifest/` | Um manifesto de tools básico |
| `mcp-config/` | Um `.mcp.json` com as duas chaves de raiz possíveis (`mcpServers` e `servers`) |
| `skill-md/` | Um `SKILL.md` normal e um sem `name` (para testar o fallback pelo nome da pasta) |
| `source-exclusion/` | O mesmo código em `src/` e em quatro lugares que devem ser pulados |
| `suppression/` | Um manifesto com quatro supressões: uma certa e três quebradas |
| `empty/` | Uma pasta vazia, para testar "não achei nada" |

### `/tests/corpus` — código real de terceiros

Manifestos, skills, código e configs **reais**, baixados de projetos públicos e
commitados aqui. A regra é uma só: **um scan desta pasta não pode produzir
nenhum achado `high` ou `critical`.**

Por que isso existe além dos fixtures limpos: um fixture é escrito por quem
escreveu a regra, na mesma hora, e por isso não consegue mostrar que a regra é
ampla demais de um jeito que essa pessoa não pensou. Código real consegue — e
conseguiu: na primeira rodada o corpus produziu 13 achados `high`, todos
falsos, e duas regras foram corrigidas por causa disso.

```
tests/corpus/
├── servers/    lista de tools capturada de 4 servidores oficiais
├── skills/     as 19 skills oficiais do anthropics/skills
├── source/     10 arquivos TypeScript de servidores reais
└── configs/    7 configs de cliente
```

Cada subpasta tem um `PROVENANCE.txt` dizendo de onde veio e em qual commit.
Nada é baixado durante os testes — só o que está commitado é lido.

---

## 6. `/docs`, `/scripts` e a raiz

### `/docs`

- **`SPEC.md`** — a especificação. É onde estão as decisões e os motivos delas,
  incluindo os falsos negativos aceitos de propósito.
- **`rules/<ID>.md`** — uma página por regra: o risco, exemplo vulnerável,
  exemplo limpo, o que a regra **não** pega, e como corrigir. Cada achado
  emitido linka para a sua página.
- **`rules/MCPSCAN001.md`** — não é uma regra de detecção: é o diagnóstico de
  comentário de supressão quebrado.
- **`ARCHITECTURE.md`** — este arquivo.

### `/scripts`

- **`capture-corpus.mjs`** — regenera o `tests/corpus/`. Rodado à mão,
  raramente. É o único lugar do projeto que baixa coisas da internet e executa
  pacotes de terceiros, e por isso fica fora do `npm test`.

### Arquivos da raiz

| Arquivo | Para que serve |
|---|---|
| `package.json` | Dependências, scripts (`test`, `typecheck`, `build`) e o binário `mcpscan` |
| `tsconfig.json` | Configuração do TypeScript. Exclui `tests/corpus` — é código de outra pessoa |
| `tsup.config.ts` | Empacota tudo num `dist/cli.js` só |
| `vitest.config.ts` | Roda `tests/**/*.test.ts`, ignorando `tests/fixtures/` |
| `action.yml` | A GitHub Action; um invólucro fino que chama `npx mcpscan` |
| `.github/workflows/` | `ci.yml` (typecheck + testes + build) e `example-usage.yml` (exemplo de uso da Action) |
| `README.md` | Documentação para quem vai usar a ferramenta |
| `CLAUDE.MD` | Contexto do produto para assistentes de IA |

---

## 7. Como as peças se chamam

Do topo para baixo, quem depende de quem:

```
cli/index.ts
   ├── config.ts ......... lê mcpscan.config.json
   ├── report/baseline.ts  lê o arquivo de baseline
   ├── scan.ts ─────────────────────────────┐
   └── report/* .......... formata a saída  │
                                            │
scan.ts                                     │
   ├── collect/index.ts ── collect/*        │
   ├── core/engine.ts ──── rules/index.ts ──┴── rules/mcp/*, rules/skill/*
   ├── core/suppress.ts                              └── rules/shared/*
   └── core/fingerprint.ts (para o baseline)
```

Duas coisas que valem saber:

- **`core/types.ts` não importa nada.** Todo mundo importa dele. É o vocabulário
  comum.
- **As regras não importam umas às outras.** Só de `core/types.ts` e às vezes de
  `rules/shared/`. Por isso dá para adicionar ou remover uma regra sem tocar em
  nenhuma outra.

---

## 8. Receitas

### Quero adicionar uma regra nova

Quatro arquivos, nesta ordem:

1. `src/rules/mcp/MCP0XX.ts` — a regra
2. `src/rules/index.ts` — adicionar à lista `RULES`
3. `tests/fixtures/MCP0XX/vulnerable/` e `clean/` — os dois fixtures
4. `docs/rules/MCP0XX.md` — a documentação

O `anti-fp.test.ts` vai cobrar os passos 3 e 4 automaticamente. Depois rode
`npm test` — se a regra nova disparar no fixture limpo de outra regra, o teste
cruzado avisa.

### Quero entender por que um achado apareceu

O `ruleId` do achado te dá o caminho: `docs/rules/<ID>.md` explica a regra em
português de gente, e `src/rules/*/<ID>.ts` é a implementação. A seção "What
this rule does NOT flag" da doc costuma responder direto.

### Quero adicionar um formato de saída

1. `src/report/meuformato.ts` — a função de formatação
2. `src/report/format.ts` — adicionar o nome à lista `FORMATS`
3. `src/cli/index.ts` — adicionar o ramo no encadeamento de formatos

### Quero rodar a ferramenta enquanto desenvolvo

```bash
npm run build              # gera dist/cli.js
node dist/cli.js ./alvo    # roda
npm test                   # todos os testes
npm run typecheck          # só o TypeScript
```

---

## 9. Vocabulário mínimo

| Termo | Significa |
|---|---|
| **finding** (achado) | Um problema encontrado: regra, local, mensagem, correção sugerida |
| **rule** (regra) | Um detector. Tem um id (`MCP004`), severidade e uma função `check()` |
| **collector** (coletor) | Traduz um arquivo em estrutura. Não julga nada |
| **subject** (sujeito) | O que uma regra recebe: uma tool, um servidor, uma skill, um arquivo de código, ou o scan inteiro |
| **ScanTarget** | Tudo que o scan encontrou, numa estrutura só |
| **severity** | `critical` · `high` · `medium` · `low` · `info` |
| **confidence** | O quanto a regra tem certeza. Limita a severidade máxima que ela pode emitir |
| **fingerprint** | Identidade estável de um achado, que não muda se a linha se mover |
| **suppression** | Comentário que silencia um achado numa linha, com motivo obrigatório |
| **baseline** | Arquivo com os achados já aceitos, para falhar só no que é novo |
| **fixture** | Exemplo que escrevemos para testar uma regra |
| **corpus** | Código real de terceiros, que não pode gerar achado grave |
