# SPEC — mcpscan (MVP)

Status: rascunho v1 · Data: 2026-08-28
Documento-fonte de escopo: `CLAUDE.md` (contexto de mercado e posicionamento).

---

## 1. Resumo em uma frase

`npx mcpscan ./meu-server` lê definições de MCP tools e agent skills num diretório, aplica um conjunto de regras de detecção ancoradas no OWASP MCP Top 10, e emite findings com arquivo+linha, severidade e correção — em texto no terminal e em SARIF no CI.

## 2. Critério de sucesso do MVP

O MVP está pronto quando um dev que nunca ouviu falar da ferramenta consegue:

1. Rodar `npx mcpscan .` num repo de MCP server e ver findings reais em menos de 30s.
2. Colar ~6 linhas de YAML num workflow e ver os findings anotados no PR via GitHub code scanning.
3. Rodar contra 10 MCP servers populares e conhecidamente limpos e receber **zero** findings `high`/`critical`.

O item 3 é o mais difícil e o mais importante. Ver §8.

## 3. Fora de escopo (explicitamente)

Dashboard web, multi-tenant, SSO/RBAC, telemetria, gateway de runtime, auto-fix, análise de fluxo de dados interprocedural, execução sandboxed do servidor por padrão.

---

## 4. Superfícies de entrada

A ferramenta recebe um caminho e precisa descobrir sozinha o que analisar. Quatro *collectors* independentes, cada um produzindo a IR normalizada (§5):

| Collector | Lê | Produz |
|---|---|---|
| `mcp-config` | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json` | `ServerDefinition[]` (transporte, comando, env, URL) |
| `mcp-manifest` | JSON/YAML com `tools: [{name, description, inputSchema}]`, respostas salvas de `tools/list` | `ToolDefinition[]` |
| `skill-md` | `**/SKILL.md` + arquivos irmãos referenciados | `SkillDefinition[]` |
| `source` | `**/*.{ts,js,mjs,py}` | `SourceFile[]` para análise de sinks |

**Collector opcional `mcp-live` (flag `--connect`, NÃO default):** sobe o servidor via stdio e chama `tools/list`. É o dado mais fiel que existe, mas **executa código não confiável** — exatamente o que estamos auditando. Por isso é opt-in explícito, com aviso na saída, e o finding gerado carrega `provenance: "live"`.

> Decisão de projeto: o MVP é **estático por padrão**. Um scanner de segurança que precisa executar o alvo para funcionar não pode ser o primeiro comando que alguém roda.

---

## 5. IR (representação intermediária)

Tudo que os collectors produzem e tudo que as regras consomem passa por estes tipos. As regras nunca tocam em arquivos — só na IR. É isso que torna cada regra uma função pura testável.

```ts
type Severity   = 'critical' | 'high' | 'medium' | 'low' | 'info';
type Confidence = 'high' | 'medium' | 'low';

interface SourceLocation {
  file: string;        // relativo ao root do scan, sempre com '/'
  line: number;        // 1-based
  column: number;      // 1-based
  endLine: number;
  endColumn: number;
  jsonPath?: string;   // 'tools[2].inputSchema.properties.path.description'
}

interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;                 // JSON Schema cru
  serverName?: string;
  origin: SourceLocation;                // onde a tool foi declarada
  loc(jsonPath: string): SourceLocation; // localização de um campo interno
}

interface ServerDefinition {
  name: string;
  transport: 'stdio' | 'http' | 'sse' | 'unknown';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  tools: ToolDefinition[];
  origin: SourceLocation;
}

interface SkillDefinition {
  name: string;
  description?: string;
  allowedTools?: string[];            // frontmatter 'allowed-tools'
  frontmatter: Record<string, unknown>;
  body: string;
  bodyOffsetLine: number;             // linha onde o corpo começa (match -> linha real)
  referencedFiles: string[];
  origin: SourceLocation;
}

interface Finding {
  ruleId: string;                     // 'MCP002'
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp?: string;                     // 'Tool Poisoning'
  location: SourceLocation;
  message: string;                    // O QUE está errado, em 1 frase
  remediation: string;                // O QUE FAZER, em 1-2 frases, acionável
  evidence?: string;                  // trecho casado, truncado em 120 chars, segredos redigidos
  helpUri: string;                    // .../docs/rules/MCP002.md
  provenance: 'static' | 'live';
}
```

### 5.1 Localização precisa é requisito, não enfeite

`JSON.parse` **destrói** a informação de posição. Sem linha exata o SARIF não anota o PR, e sem anotação no PR a ferramenta não entra no fluxo de ninguém.

- JSON/JSONC → `jsonc-parser` (Microsoft, zero deps) → AST com `offset`/`length` por nó.
- YAML / frontmatter → `yaml` (eemeli) → CST com ranges.
- Markdown (corpo de SKILL.md) → offset do match + `bodyOffsetLine`.
- Offset → linha/coluna via um índice de quebras de linha construído uma vez por arquivo.

`src/core/location.ts` é o único lugar que faz essa conversão.

---

## 6. Motor de regras

```ts
interface Rule<T> {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp?: string;
  appliesTo: 'tool' | 'server' | 'skill' | 'sourceFile' | 'target';
  check(subject: T, ctx: ScanContext): Finding[];   // pura, síncrona, sem I/O
}
```

Regras são registradas num array explícito em `src/rules/index.ts`. O engine itera `subjects × rules` e concatena findings. Sem herança, sem DI, sem descoberta dinâmica de plugin no MVP — um array explícito é mais fácil de ler, de testar e de tree-shakear.

### 6.1 Invariante anti-falso-positivo

O engine aplica um teto: **uma regra com `confidence: 'low'` nunca emite severidade acima de `medium`; só `confidence: 'high'` pode emitir `critical`.** Isso é verificado por teste no registry, não por disciplina humana.

---

## 7. Catálogo de regras do MVP

`→ FP` = o risco de falso positivo e como ele é mitigado.

### MCP servers

| ID | Nome | Sev | Conf | O que detecta |
|---|---|---|---|---|
| **MCP002** | `hidden-unicode-in-tool` | critical | high | Zero-width (U+200B–200D, U+FEFF), tag chars (U+E0000–E007F), bidi overrides (U+202A–202E, U+2066–2069) em `name`/`description`/schema. → FP ≈ 0: não existe motivo legítimo. **Primeira regra a implementar.** |
| **MCP001** | `tool-description-injection` | critical | high | Diretivas dirigidas ao modelo dentro de `description`: `<IMPORTANT>`, "ignore previous instructions", "do not tell the user", "before calling any other tool", "não mencione". → FP: exige padrão imperativo **e** alvo (modelo/usuário), não palavra solta. |
| **MCP003** | `schema-field-injection` | critical | high | O mesmo padrão do MCP001, mas dentro de `inputSchema.properties.*.description` / `default` / `enum`. Campo de schema é lugar ainda menos legítimo para prosa imperativa. |
| **MCP004** | `unconstrained-path-parameter` | high | medium | Param `string` cujo nome casa `path\|file\|filename\|dir\|target` **e** sem `pattern`/`enum`/`format` **e** a tool descreve leitura/escrita de arquivo. → FP: as três condições juntas; sem a terceira vira ruído. |
| **MCP005** | `command-injection-surface` | critical | medium | Param que alimenta shell: nome casa `cmd\|command\|shell\|script\|exec`, ou tool nomeada `run_*`/`exec_*` com param string livre. |
| **MCP008** | `dangerous-sink-in-source` | high | medium | No código-fonte: `eval(`, `new Function(`, `child_process.exec(` com template literal, `fs.readFile` com valor vindo direto de `request.params.arguments`. |
| **MCP006** | `tool-shadowing` | high | medium | Duas tools com o mesmo nome em servers diferentes; ou `description` de uma tool citando o nome de outra com verbo imperativo ("when using `send_email`, first call…"). |
| **MCP007** | `unpinned-server-provenance` | medium | high | Config com `npx -y pkg` sem versão fixa, `@latest`, `curl \| sh` no comando, ou URL `http://` sem TLS. |
| **MCP009** | `secret-in-mcp-config` | high | high | Valor em `env` que casa formato de credencial conhecido (`sk-`, `ghp_`, `AKIA`, JWT). Evidência sempre redigida. |

### Agent skills

| ID | Nome | Sev | Conf | O que detecta |
|---|---|---|---|---|
| **SKILL001** | `hidden-instructions-in-skill` | critical | high | Comentário HTML `<!-- … -->` contendo imperativo dirigido ao modelo; unicode invisível; blob base64 > 200 chars sem contexto. |
| **SKILL002** | `skill-description-injection` | critical | high | MCP001 aplicado ao `description` do frontmatter — é o campo que o modelo lê sem o usuário ver. |
| **SKILL003** | `undeclared-capability` | high | medium | Corpo instrui `curl`/`wget`/`rm -rf`/escrita fora do diretório do skill, mas `allowed-tools` no frontmatter não declara a capacidade correspondente. |
| **SKILL004** | `remote-code-fetch` | high | high | `curl … \| sh`, `iwr … \| iex`, download de `raw.githubusercontent.com` sem commit SHA fixo. |

Cada regra tem `docs/rules/<ID>.md` com: exemplo vulnerável, exemplo limpo, por que é risco, como corrigir, como suprimir. O `helpUri` do finding aponta pra lá.

---

## 8. Controle de falso positivo (o requisito que mata o produto se falhar)

Três mecanismos, todos automatizados:

1. **Fixture par obrigatório.** Toda regra tem `tests/fixtures/<ID>/vulnerable/` e `tests/fixtures/<ID>/clean/`. Um teste no registry falha se alguma regra registrada não tiver ambos.
2. **Corpus de regressão.** `tests/corpus/` contém manifests reais de MCP servers populares conhecidamente limpos (commitados como fixtures, não baixados em runtime). Teste: `scan(corpus)` retorna **zero** findings `high`/`critical`. Regra nova que quebre esse teste não entra.
3. **Supressão com justificativa obrigatória.**
   `// mcpscan-disable-next-line MCP004 -- path é validado em validatePath()`
   Sem o `--` e o motivo, a supressão é ignorada e vira finding `info` de "supressão malformada".

---

## 9. CLI

```
mcpscan [path]                       # default: '.'

  --format <fmt>      pretty | json | sarif | github   (default: pretty se TTY, json se não)
  --output <file>     escreve no arquivo em vez do stdout
  --fail-on <sev>     critical | high | medium | low | none   (default: high)
  --rules <ids>       lista separada por vírgula; roda só estas
  --disable <ids>     desliga regras específicas
  --connect           sobe o server e usa tools/list (executa código do alvo — opt-in)
  --baseline <file>   ignora findings já presentes no baseline
  --config <file>     default: mcpscan.config.json
  --no-color
  --quiet
```

**Exit codes** (contrato estável — o CI depende disso):

| Código | Significado |
|---|---|
| 0 | Nenhum finding no nível de `--fail-on` ou acima |
| 1 | Findings no nível de `--fail-on` ou acima |
| 2 | Erro de execução (caminho inválido, config inválida, crash) |

Distinguir 1 de 2 importa: `1` é "achei problema", `2` é "não consegui olhar". Um CI que trata os dois igual esconde scanner quebrado como se fosse repo limpo.

### 9.1 Saída `pretty`

```
mcpscan v0.1.0 · 3 arquivos · 12 tools · 1 skill

CRITICAL  MCP002  Caractere Unicode invisível na descrição da tool
  src/tools.json:14:32  tools[1].description
  Encontrado U+E0041 (tag character) entre "arquivo" e "do".
  Fix: remova caracteres invisíveis. A descrição é lida pelo modelo, não pelo
       usuário — texto invisível ali é instrução oculta.
  https://.../docs/rules/MCP002.md

  1 critical · 0 high · 0 medium
  Falhou: --fail-on=high
```

Regras da saída: severidade primeiro, localização clicável em `file:line:col`, `Fix:` sempre presente, link sempre presente. Sem banner ASCII, sem emoji, sem spinner.

---

## 10. SARIF

Prioridade desde a Fase 2 — é o que faz plugar em GitHub code scanning sem esforço do usuário.

- `runs[].tool.driver.rules[]` — um por regra registrada, com `id`, `name`, `shortDescription`, `fullDescription`, `helpUri`, `defaultConfiguration.level`.
- `runs[].results[]` — `ruleId`, `level`, `message.text`, `locations[].physicalLocation` com `artifactLocation.uri` (relativo, `/`) e `region` (`startLine`, `startColumn`, `endLine`, `endColumn`).
- `partialFingerprints["mcpScan/v1"]` = hash(ruleId + caminho + jsonPath + evidência normalizada).
  **Sem fingerprint estável o GitHub reabre o mesmo alerta a cada commit** e o usuário desliga a ferramenta. O fingerprint **não pode** incluir número de linha — senão qualquer edição acima gera alerta novo.

Severidade → SARIF `level`: critical/high → `error`, medium → `warning`, low/info → `note`.

---

## 11. GitHub Action

`action.yml` na raiz, para uso direto `uses: <user>/mcpscan@v1`:

```yaml
- uses: <user>/mcpscan@v1
  with:
    path: .
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpscan.sarif
```

A Action é um wrapper fino: roda `npx mcpscan --format sarif --output mcpscan.sarif`. Nenhuma lógica nova.

---

## 12. Stack

| Peça | Escolha | Por quê |
|---|---|---|
| Linguagem | TypeScript, ESM, Node ≥ 20 | Distribuição npm/npx é o canal |
| Testes | Vitest | Rápido, ESM nativo, snapshot embutido |
| Build | tsup → bundle único ESM | `npx` de pacote não-bundlado é lento; startup é UX |
| JSON c/ posição | `jsonc-parser` | Zero deps, AST com offsets |
| YAML c/ posição | `yaml` | CST com ranges |
| Glob | `tinyglobby` | Leve |
| CLI | `commander` | Padrão, previsível |
| Cor | `picocolors` | ~2 kB |

Alvo: **≤ 8 dependências de runtime**. Cada dependência é superfície de ataque numa ferramenta de segurança e latência no `npx`.

---

## 13. Estrutura de arquivos

```
src/
  cli/index.ts           # parse de args, orquestra, define exit code
  core/types.ts          # IR (§5) — sem lógica
  core/location.ts       # offset -> line/col; construção de SourceLocation
  core/engine.ts         # subjects x rules -> Finding[]; aplica teto de confiança
  core/config.ts         # carrega mcpscan.config.json, merge com flags
  core/suppress.ts       # parse de mcpscan-disable-next-line
  collect/mcp-config.ts
  collect/mcp-manifest.ts
  collect/skill-md.ts
  collect/source.ts
  collect/index.ts       # discover(root) -> ScanTarget
  rules/index.ts         # registry (array explícito)
  rules/mcp/MCP001.ts ... rules/skill/SKILL004.ts
  rules/shared/patterns.ts   # regex de injeção compartilhados, UM lugar só
  report/pretty.ts
  report/json.ts
  report/sarif.ts
  report/github.ts
tests/
  fixtures/<RULE_ID>/{vulnerable,clean}/
  corpus/                # manifests reais limpos, para regressão de FP
docs/
  rules/<RULE_ID>.md
action.yml
```

---

## 14. Riscos conhecidos

| Risco | Mitigação |
|---|---|
| Falso positivo destrói confiança | §8: corpus de regressão + teto de confiança + fixture par |
| `--connect` executa código malicioso | Opt-in, aviso explícito, nunca no default nem na Action |
| Formato de manifest MCP evolui | Collectors isolados; regras dependem só da IR |
| Regex de injeção vira gato-e-rato | Aceitar: o MVP pega o caso não-adversarial (os 36,82% da Snyk são majoritariamente erro, não ataque dirigido). Documentar a limitação no README em vez de fingir cobertura. |
| Ninguém instala | Fase 2 (SARIF + Action) **antes** da regra nº 2 — distribuição antes de profundidade |

---

## 15. Pontos que precisam de verificação antes de codar

- **IDs oficiais do OWASP MCP Top 10.** O CLAUDE.md cita as categorias por nome (tool poisoning, schema poisoning, tool shadowing, shadow servers) mas não os identificadores. Confirmar a numeração no documento OWASP atual antes de gravar `owasp:` em cada regra — número errado num relatório de segurança é pior que número nenhum.
- ~~**Nome no npm.**~~ **Resolvido em 2026-08-28:** `mcp-scan` está tomado (v2.0.6, Invariant Labs — scanner de MCP concorrente direto) e `mcp-scanner` também. Nome escolhido: **`mcpscan`** (livre). Binário `mcpscan`, diretiva `mcpscan-disable-next-line`, config `mcpscan.config.json`.
- **Formato canônico de `SKILL.md`.** Confirmar as chaves reais de frontmatter (`name`, `description`, `allowed-tools`) contra a spec atual de agent skills antes de escrever `collect/skill-md.ts`.
