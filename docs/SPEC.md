# SPEC — mcpscan (MVP)

Status: draft v1 · Date: 2026-08-28
Scope source document: `CLAUDE.md` (market context and positioning).

---

## 1. One-sentence summary

`npx mcpscan ./my-server` reads MCP tool and agent skill definitions in a directory, applies a set of detection rules anchored in the OWASP MCP Top 10, and emits findings with file+line, severity, and a fix — as terminal text, and as SARIF in CI.

## 2. MVP success criteria

The MVP is ready when a dev who's never heard of the tool can:

1. Run `npx mcpscan .` in an MCP server repo and see real findings in under 30s.
2. Paste ~6 lines of YAML into a workflow and see findings annotated on the PR via GitHub code scanning.
3. Run it against 10 popular, known-clean MCP servers and get **zero** `high`/`critical` findings.

Item 3 is the hardest and most important. See §8.

## 3. Out of scope (explicitly)

Web dashboard, multi-tenant, SSO/RBAC, telemetry, runtime gateway, auto-fix, interprocedural data-flow analysis, sandboxed server execution by default.

---

## 4. Input surfaces

The tool receives a path and has to figure out on its own what to analyze. Four independent *collectors*, each producing the normalized IR (§5):

| Collector | Reads | Produces |
|---|---|---|
| `mcp-config` | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json` | `ServerDefinition[]` (transport, command, env, URL) |
| `mcp-manifest` | JSON/YAML with `tools: [{name, description, inputSchema}]`, saved `tools/list` responses | `ToolDefinition[]` |
| `skill-md` | `**/SKILL.md` + referenced sibling files | `SkillDefinition[]` |
| `source` | `**/*.{ts,js,mjs,py}` | `SourceFile[]` for sink analysis |

**Optional collector `mcp-live` (`--connect` flag, NOT default):** starts the server over stdio and calls `tools/list`. It's the most faithful data there is, but it **runs untrusted code** — exactly what we're auditing. That's why it's explicit opt-in, with a warning in the output, and the resulting finding carries `provenance: "live"`.

> Project decision: the MVP is **static by default**. A security scanner that needs to run its target to work can't be the first command someone runs.

---

## 5. IR (intermediate representation)

Everything the collectors produce and everything the rules consume passes through these types. Rules never touch files — only the IR. That's what makes every rule a testable pure function.

```ts
type Severity   = 'critical' | 'high' | 'medium' | 'low' | 'info';
type Confidence = 'high' | 'medium' | 'low';

interface SourceLocation {
  file: string;        // relative to the scan root, always with '/'
  line: number;        // 1-based
  column: number;      // 1-based
  endLine: number;
  endColumn: number;
  jsonPath?: string;   // 'tools[2].inputSchema.properties.path.description'
}

interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;                 // raw JSON Schema
  serverName?: string;
  origin: SourceLocation;                // where the tool was declared
  loc(jsonPath: string): SourceLocation; // location of an inner field
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
  bodyOffsetLine: number;             // line where the body starts (match -> real line)
  referencedFiles: string[];
  origin: SourceLocation;
}

interface Finding {
  ruleId: string;                     // 'MCP002'
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp?: string;                     // 'MCP03:2025 – Tool Poisoning'
  location: SourceLocation;
  message: string;                    // WHAT is wrong, in 1 sentence
  remediation: string;                // WHAT TO DO, in 1-2 actionable sentences
  evidence?: string;                  // matched excerpt, truncated to 120 chars, secrets redacted
  helpUri: string;                    // .../docs/rules/MCP002.md
  provenance: 'static' | 'live';
}
```

### 5.1 Precise location is a requirement, not a nicety

`JSON.parse` **destroys** position information. Without an exact line, SARIF can't annotate the PR, and without a PR annotation the tool doesn't enter anyone's workflow.

- JSON/JSONC → `jsonc-parser` (Microsoft, zero deps) → AST with `offset`/`length` per node.
- YAML / frontmatter → `yaml` (eemeli) → CST with ranges.
- Markdown (SKILL.md body) → match offset + `bodyOffsetLine`.
- Offset → line/column via a line-break index built once per file.

`src/core/location.ts` is the only place that does this conversion.

---

## 6. Rule engine

```ts
interface Rule<T> {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp?: string;
  appliesTo: 'tool' | 'server' | 'skill' | 'sourceFile' | 'target';
  check(subject: T, ctx: ScanContext): Finding[];   // pure, synchronous, no I/O
}
```

Rules are registered in an explicit array in `src/rules/index.ts`. The engine iterates `subjects × rules` and concatenates findings. No inheritance, no DI, no dynamic plugin discovery in the MVP — an explicit array is easier to read, test, and tree-shake.

### 6.1 Confidence ceiling

The engine applies a ceiling: **a rule with `confidence: 'low'` never emits a severity above `medium`; only `confidence: 'high'` can emit `critical`.** This is verified by a test on the registry, not by human discipline.

> **What this ceiling is NOT.** It constrains the *metadata the rule author writes*, not the rule's actual precision. MCP002 declared itself `critical`/`high` — the ceiling was a no-op — and it still had four classes of false positive (§7.2). The ceiling prevents publishing `critical`/`low`; it is **not** the defense against false positives. That defense is the breadth of each rule's negative fixtures (§8) and the regression corpus.

**A rule must declare the severity it actually emits.** The engine clamps at runtime, but `tests/anti-fp.test.ts` additionally rejects any rule whose *declared* severity exceeds its confidence ceiling. Declaring `critical` with `confidence: 'medium'` and silently being emitted as `high` is the same class of metadata lie the ceiling exists to prevent — and the declared value is what reaches SARIF's `defaultConfiguration.level`, so the two must agree. MCP005 was specified as `critical`/`medium` and was corrected to `high`/`medium` for this reason, before it was implemented.

### 6.2 `appliesTo` and the subject's type

`Rule` is a **union discriminated by `appliesTo`**, not a free generic `Rule<S>`:

```ts
export type Rule =
  | { appliesTo: 'tool';       check(s: ToolDefinition,   ctx: ScanContext): PartialFinding[] }
  | { appliesTo: 'skill';      check(s: SkillDefinition,  ctx: ScanContext): PartialFinding[] }
  | { appliesTo: 'server';     check(s: ServerDefinition, ctx: ScanContext): PartialFinding[] }
  | { appliesTo: 'sourceFile'; check(s: SourceFile,       ctx: ScanContext): PartialFinding[] }
  | { appliesTo: 'target';     check(s: ScanTarget,       ctx: ScanContext): PartialFinding[] }
  ;  // + the common fields id/title/severity/confidence/owasp
```

With a generic `Rule<S>`, a rule declaring `appliesTo: 'tool'` but typed as `Rule<SkillDefinition>` **compiled without error** (method-parameter bivariance), the engine would pass a `ToolDefinition`, and `subject.body.slice()` would throw at runtime — straight into the false-clean of §9. The union moves that error to typecheck. `PartialFinding` is exported from `core/types.ts` exactly once: repeating the `Omit<...>` in every rule would let a rule silently regain the right to set its own severity.

---

## 7. MVP rule catalog

`→ FP` = the false-positive risk and how it's mitigated.

### MCP servers

| ID | Name | Sev | Conf | What it detects |
|---|---|---|---|---|
| **MCP002** | `hidden-unicode-in-tool` | critical | high | Invisible characters in `name`/`description`/schema, with a per-class policy — see §7.2. **First rule to implement.** |
| **MCP001** | `tool-description-injection` | critical | high | Model-directed directives inside `description`: `<IMPORTANT>`, "ignore previous instructions", "do not tell the user", "before calling any other tool", "don't mention". → FP: requires an imperative pattern **and** a target (model/user), not a standalone word. |
| **MCP003** | `schema-field-injection` | critical | high | The same pattern as MCP001, but inside `inputSchema.properties.*.description` / `default` / `enum`. A schema field is an even less legitimate place for imperative prose. |
| **MCP004** | `unconstrained-path-parameter` | high | medium | A `string` param whose name matches `path\|file\|filename\|dir\|target` **and** has no `pattern`/`enum`/`format` **and** the tool describes reading/writing a file. → FP: all three conditions together; without the third it becomes noise. |
| **MCP005** | `command-injection-surface` | high | medium | A param feeding a shell: name matches `cmd\|command\|shell\|script\|exec`, or a tool named `run_*`/`exec_*` with a free-form string param. |
| **MCP008** | `dangerous-sink-in-source` | high | medium | In source code: `eval(`, `new Function(`, `child_process.exec(` with a template literal, `fs.readFile` with a value coming straight from `request.params.arguments`. |
| **MCP006** | `tool-shadowing` | high | medium | Two tools with the same name on different servers; or a tool's `description` naming another tool with an imperative verb ("when using `send_email`, first call…"). |
| **MCP007** | `unpinned-server-provenance` | medium | high | Config with `npx -y pkg` without a pinned version, `@latest`, an untagged or `:latest` `docker run` image, `curl \| sh` in the command, or an unencrypted `http://` URL. |
| **MCP010** | `dangerous-sink-in-python-source` | high | medium | MCP008's sibling for Python: `eval`/`exec`, `os.system`/`os.popen`/`subprocess` with a built command, and deserialisation that runs code while decoding (`pickle`, `marshal`, `yaml.load` with no `Loader=`). Added after a scan of `awslabs/mcp` — 111 files at the time — reported **two** source files, because those were the only two that were not Python. |
| **MCP009** | `secret-in-mcp-config` | high | high | A known credential format (`sk-`, `ghp_`, `AKIA`, JWT) in `env`, in a server `url`'s query string, or in `command`/`args`. Evidence always redacted. |

### Agent skills

| ID | Name | Sev | Conf | What it detects |
|---|---|---|---|---|
| **SKILL001** | `hidden-instructions-in-skill` | critical | high | An HTML comment `<!-- … -->` containing a model-directed imperative; invisible unicode; a base64 blob > 200 chars with no context. |
| **SKILL002** | `skill-description-injection` | critical | high | MCP001 applied to the frontmatter `description` — the field the model reads without the user seeing it. |
| **SKILL003** | `undeclared-capability` | high | medium | The body instructs `curl`/`wget`/`rm -rf`/writes outside the skill's directory, but `allowed-tools` in the frontmatter doesn't declare the matching capability. |
| **SKILL004** | `remote-code-fetch` | high | high | `curl … \| sh`, `iwr … \| iex`, a download from `raw.githubusercontent.com` without a pinned commit SHA. |

### 7.2 MCP002 — per-character-class policy

> **2026-08-28 correction.** The first spec for this rule — "flag every U+200B–200D, U+2060, U+FEFF, U+202A–202E, U+2066–2069" — was implemented and **failed review with four reproduced classes of false positive**. Recorded here because the mistake is instructive: "invisible character" looks like a binary category, and it isn't.
>
> | Legitimate input | Triggered | Why it's legitimate |
> |---|---|---|
> | `Faz deploy 👩‍💻 rapido` | U+200D | Every emoji ZWJ sequence uses U+200D |
> | `می‌شود` (Persian) | U+200C | ZWNJ is **required spelling** in Persian and in Devanagari-family scripts |
> | `اقرأ ⁨read_file⁩ ملف` | U+2068/U+2069 | Isolates are what **UAX #9 recommends** for embedding a Latin identifier in RTL text |
> | `👨‍👩‍👧 🏳️‍🌈` | U+200D | Same as emoji |
>
> A scanner that marks CRITICAL on a Persian description loses the user on the first run.

**Always flag** — no legitimate use in machine-read text:

| Class | Codepoints |
|---|---|
| Tag characters | U+E0000–E007F |
| Zero-width space / word joiner / BOM in the middle of the string | U+200B, U+2060, U+FEFF |
| Bidi overrides | U+202D (LRO), U+202E (RLO) — force direction regardless of the character's class; this is the Trojan Source vector (CVE-2021-42574). Suspicious even when balanced. |
| Run of variation selectors | ≥ 3 consecutive in U+FE00–FE0F or U+E0100–E01EF. A single isolated `U+FE0F` is emoji presentation and does **not** trigger. |

**Flag only in context** — the character itself is legitimate, the usage is what gives it away:

| Class | Trigger condition |
|---|---|
| ZWJ / ZWNJ (U+200C, U+200D) | Only when **both** neighbors are ASCII/Latin. Between emoji, or between Arabic/Indic letters, it's normal usage. |
| Bidi embeddings (U+202A LRE, U+202B RLE / U+202C PDF) | Only when **unbalanced** in the string |
| Bidi isolates (U+2066 LRI, U+2067 RLI, U+2068 FSI / U+2069 PDI) | Only when **unbalanced** in the string |

**Never flag:** directional marks U+200E (LRM) and U+200F (RLM) — routine, harmless use in bidirectional text.

The four legitimate entries in the table above are **mandatory negative fixtures** for MCP002.

#### Known and accepted evasion gap

The "both neighbors Latin" condition for ZWJ/ZWNJ leaves a seam: `read` + ZWJ + `😀` + hidden text **does not trigger**, because the right neighbor isn't Latin. Confirmed by reproduction.

Closing this would require switching to "**at least one** Latin neighbor". No known legitimate use of ZWJ/ZWNJ has a Latin neighbor — in an emoji sequence both sides are emoji, in Persian and Devanagari both sides are the same script — so the change is *probably* safe. It stays a **candidate hardening, not applied**, until Task 28 has a real corpus to measure against. In a rule whose entire value is not generating false positives, "probably safe" isn't enough to touch precision.

This is consistent with the limitation already stated in §14: against an adaptive attacker who knows the rules, a pattern matcher doesn't hold up. The README says so; the alternative — pretending to have coverage — costs more trust than the gap does.

### 7.1 Mapping to the OWASP MCP Top 10 (2025)

IDs verified on 2026-08-28 against <https://owasp.org/www-project-mcp-top-10/>. Each rule's `owasp` field uses the exact string from this table — never a made-up label.

| OWASP | Official title | Rules |
|---|---|---|
| `MCP01:2025` | Token Mismanagement & Secret Exposure | MCP009 |
| `MCP02:2025` | Privilege Escalation via Scope Creep | MCP004, SKILL003 |
| `MCP03:2025` | Tool Poisoning | MCP001, MCP002, MCP003, MCP006 |
| `MCP04:2025` | Software Supply Chain Attacks & Dependency Tampering | MCP007, SKILL004 |
| `MCP05:2025` | Command Injection & Execution | MCP005, MCP008, MCP010 |
| `MCP06:2025` | Intent Flow Subversion | — |
| `MCP07:2025` | Insufficient Authentication & Authorization | — |
| `MCP08:2025` | Lack of Audit and Telemetry | — (out of scope: it's the enterprise layer) |
| `MCP09:2025` | Shadow MCP Servers | — **known gap, see below** |
| `MCP10:2025` | Context Injection & Over-Sharing | SKILL001, SKILL002 |

"Schema poisoning" and "tool shadowing" are **not their own categories** in the OWASP MCP Top 10 — they're sub-techniques of `MCP03:2025 – Tool Poisoning`. MCP003 and MCP006 both map to MCP03 and are told apart by the rule's `title`.

**Accepted gap in the MVP — `MCP09:2025 Shadow MCP Servers`.** CLAUDE.md asks for "shadow servers" in scope, but the MVP doesn't really cover it: MCP007 detects *unpinned provenance* (supply chain, MCP04), which is adjacent but different. Truly detecting a shadow server requires comparing what's declared against what actually responds — which depends on the `mcp-live` collector (`--connect`), which was left out of the MVP because it runs untrusted code. Document the gap in the README instead of implying it's covered.

Every rule has `docs/rules/<ID>.md` with: a vulnerable example, a clean example, why it's a risk, how to fix it, how to suppress it. The finding's `helpUri` points there.

### 7.3 Two families of rule, and why they need different severities

| Family | Rules | Detects | Confidence | Evidence |
|---|---|---|---|---|
| **Payload** | MCP001, MCP002, MCP003, SKILL001, SKILL002 | Text that should not be there | `high` | Unambiguous. Nobody writes `<IMPORTANT>ignore previous instructions</IMPORTANT>` into a tool description by accident. |
| **Risk surface** | MCP004, MCP005, MCP006, MCP008, SKILL003 | A schema or shape that *permits* something dangerous | `medium` | Circumstantial. A `path` with no `pattern` does not mean the tool has arbitrary file read — it means nothing in the contract prevents it. |

Risk-surface rules **will flag correct code sometimes, by construction.** That is not a defect; it is what the family detects. Three consequences follow, and all three are load-bearing:

1. `confidence: 'medium'` caps them at `high` — a risk-surface rule may never emit `critical`.
2. Each requires **several conditions to coincide** before firing. MCP004 needs all three of: a path-shaped parameter name, no schema constraint, and a tool that is demonstrably a file tool. Drop any one and the rule becomes noise.
3. Their `What this rule does NOT flag` documentation section matters more than for payload rules, because a developer whose safe code was flagged needs to see immediately which schema would have satisfied the rule.

The failure mode to avoid is treating both families alike and giving risk surface a `critical`. A developer who gets a CRITICAL for naming a parameter `path` stops trusting the tool, and then never looks at the payload findings either — which were the correct ones.

### 7.4 Accepted false negatives

These are known misses. All fail in the safe direction — silence rather than noise — which is the trade this project deliberately makes.

| Rule | Miss | Why it is accepted |
|---|---|---|
| MCP004 | A genuine file tool whose file verb and file noun sit more than 4 tokens apart | The proximity window separates `Reads a file from disk` from `…open network connections. See also the file-based variant.` Widening it re-admits the second. |
| MCP004, MCP005 | Non-English tool descriptions | The verb/noun lists are English. Condition 3 simply will not match. |
| MCP004, MCP005 | Parameters declared via `$ref` into `$defs` rather than inline in `properties` | These two rules need structural fields (`type`, `pattern`, `items`), not just text, so they do not reuse `schema-walk.ts`. Resolving `$ref` is future hardening. |
| MCP004, MCP005 | `type: ['string', 'null']` — the array-of-types JSON Schema form | Uncommon but valid. Both rules compare `type === 'string'`. |
| MCP001, MCP003, SKILL002 | ZWJ/ZWNJ evasion with a non-Latin neighbour | See §7.2. |
| MCP006 (detection 1) | A real name collision where **neither, or only one**, of the colliding manifests declares an explicit root `"name"` | Detection 1 only compares `ToolDefinition.serverNameSource === 'declared'` tools — a name this scanner *derived* from a containing directory is a guess it made, not evidence any client loads that manifest alongside another. Comparing derived names is exactly what produced the original bug: unrelated fixture/example directories that happen to share a filename got reported as "different servers." The narrower rule trades this miss for eliminating that noise; see `docs/rules/MCP006.md`. Detecting the undeclared case for real requires comparing what's declared against what responds — the `--connect` collector, out of MVP scope (the same `MCP09:2025 Shadow MCP Servers` gap noted above). |
| MCP004 | Any path parameter in a manifest where **some** tool declares a directory restriction ("Only works within allowed directories") | The declaration exempts every path parameter in that file, including a tool the allow-list may not actually cover, and a manifest can state a restriction it does not enforce. Measured against the regression corpus (§8.2), the alternative was **nine** `high` findings on the official `@modelcontextprotocol/server-filesystem` — a rule that fires on every correctly built file server is a tax on the category, not a signal. Confirming enforcement means running the server (`--connect`, out of MVP scope). See `docs/rules/MCP004.md`. |
| SKILL004 | A skill fetching a `.md`/`.txt`/`.rst`/`.adoc` file from a mutable ref, whose content the model then acts on | This rule is *remote code fetch*; a document is read, not run. The corpus produced four `high` findings on the official `mcp-builder` skill, all of them the MCP SDK's `README.md` fetched from `main`. Remote text pulled into context is a prompt-injection risk (SKILL001/SKILL002's subject), not a supply-chain one — the finding was filed under the wrong rule, not merely noisy. See `docs/rules/SKILL004.md`. |
| MCP007 | A `docker run` whose image the rule cannot identify — an unusual value-taking flag before it, or a dynamically built invocation | Docker *is* covered now (a bare or `:latest` image fires), but finding the image means walking past flags, and an unrecognised shape produces no finding rather than a guess. See `docs/rules/MCP007.md`. |
| MCP009 | A credential in a config field other than `env`, `url`, `command` or `args` | Those four are where secrets actually get written. Anything else — a nested vendor-specific block, say — is not searched. |
| MCP006 (detection 1b) | Two servers that resolve to the same package but are declared in **two different** config files | Only entries within *one* config file are compared — nothing establishes that two separate config files are ever loaded by the same client. |
| MCP006 (detection 2) | An imperative and the target tool's name separated by more than 6 tokens | Same trade-off as MCP004's proximity window: widening it re-admits ordinary prose that happens to mention both an imperative word and a tool name in the same paragraph without one directing the other. |
| MCP006 (detection 2) | A directed tool named 4 characters or fewer (`get`, `run`, `list`, ...) | The minimum-name-length guard exists specifically to keep short, common-English tool names from matching everyday imperative prose that has nothing to do with tool redirection. |
| MCP008 | A sink reached through indirection — `const run = eval; run(x)`, a re-exported alias, or `globalThis['ev' + 'al'](x)` | Pattern matching over raw text has no notion of aliasing or dynamic property construction. |
| MCP008 | No proof that a flagged sink's argument actually derives from a tool call's arguments | This is the rule's defining limitation, not an edge case — see `docs/rules/MCP008.md`. It is why the rule is risk-surface (`confidence: 'medium'`), not payload. |
| MCP008 | Sinks in a `SourceFile` whose `language` is neither `ts`/`js` nor `py` | Python is now MCP010's subject; every other language is still uncollected and unscanned. |
| MCP010 | A sink reached through `from subprocess import run` — no `subprocess.` prefix to match | The same aliasing blindness MCP008 has, and it costs more here: `from x import y` is far more common in Python than its JavaScript equivalent. |
| MCP010 | A command assembled in a variable and then passed in — `os.system(cmd)` | A bare variable says nothing about where its value came from; firing on it would flag every server that builds argv in a helper. Deliberate under-detection, matching MCP008's treatment of `exec(cmd)`. |
| MCP008 | A real sink inside a test file (`tests/`, `test/`, `__tests__/`, `__mocks__/`, `spec/` path segment, or a `*.test.*`/`*.spec.*` basename) | The source collector (`isTestFile()` in `src/collect/source.ts`) excludes test files before a `SourceFile` is even produced, for every current and future source rule, not just MCP008. Test code never runs in front of an agent, so a sink inside it is not deployed code and not a real finding — the same reasoning MCP001–MCP006 apply implicitly by only shipping rules over manifests/skills a client actually loads. |

**Accepted false positive (the inverse case, listed here because it is the direct counterpart of the row above): MCP008 matches its own source.** A self-scan of `src/` reports four findings, all in `src/rules/mcp/MCP008.ts`, all from the rule writing `eval()` and `new Function()` inside its own `message` and `remediation` strings.

Comments no longer count — both MCP008 and MCP010 blank comment bodies before matching, which is what removed the noisiest half of this class (and, in MCP010's case, the only finding a scan of 1161 real Python files produced). **String contents are masked in MCP010 but not in MCP008**, and the asymmetry is deliberate: Python's string literals are unambiguous, JavaScript's are not, because a regex literal such as `/["']/` contains a quote that starts no string and cannot be told from a division without a parser. Masking on a wrong guess swallows real code and becomes a silent false negative — strictly worse than the noise it removes.

So four findings remain, and contorting the rule's own strings to dodge its own patterns is judged worse than the finding. This is the permanent line item in mcpscan's self-scan.

Each entry is a candidate for hardening once the regression corpus (§8.2) exists to measure against. None should be closed speculatively — that is how MCP002 acquired four false-positive classes in the first place.

---

## 8. False-positive control (the requirement that kills the product if it fails)

Three mechanisms, all automated:

1. **Mandatory fixture pair.** Every rule has `tests/fixtures/<ID>/vulnerable/` and `tests/fixtures/<ID>/clean/`. A registry test fails if any registered rule is missing either.
2. **Regression corpus.** `tests/corpus/` holds real manifests from popular, known-clean MCP servers (committed as fixtures, not downloaded at runtime). Test: `scan(corpus)` returns **zero** `high`/`critical` findings. A new rule that breaks this test doesn't ship.
3. **Suppression with a mandatory justification.**
   `// mcpscan-disable-next-line MCP004 -- path is validated in validatePath()`
   Without the `--` and the reason, the suppression is ignored and becomes an `info` finding for "malformed suppression".

   **Shipped**, in `src/collect/suppression.ts` (parse) and `src/core/suppress.ts` (apply),
   reported under `MCPSCAN001` — its own namespace, deliberately not `MCP###`/`SKILL###`,
   because it says nothing about the scanned server's security, only that an annotation in
   it is unusable. It is not in the rule registry and so cannot be selected with `--rules`
   or turned off with `--disable`. Full behaviour in `docs/rules/MCPSCAN001.md`.

   The marker is matched inside any comment syntax (`//`, `#`, `<!-- -->`, block comments)
   rather than per file type: a manifest, a `SKILL.md` and a server implementation are three
   grammars, and the annotation should read the same in all of them. What keeps that from
   matching every *mention* of the marker is that it must **start** a comment — nothing but
   whitespace and comment punctuation before it on the line. Without that guard this
   scanner's own source, which necessarily writes the marker in string literals and doc
   comments, produced three `info` findings on a self-scan; with it, a self-scan of `src/`
   is back to the single documented MCP008 self-match (§7.4). The remaining edge is a
   markdown bullet (`- mcpscan-disable-next-line ...`), since `-` is also comment
   punctuation — recorded in `docs/rules/MCPSCAN001.md`, not guarded against.

   Three defects report instead of silencing, not one:

   | Comment | Outcome |
   |---|---|
   | no `--`, or an empty reason | ignored, reported |
   | names no rule (`mcpscan-disable-next-line -- reason`) | ignored, reported. A blanket suppression would silence every rule written *after* it, which is broader than this defines |
   | names a rule that does not exist (`MCP404`) | ignored, reported, with the valid ids listed. This is the silent-typo failure: it looks like protection and provides none, the same reason §9 makes an unknown `--rules` id exit 2 |

   Two decisions worth stating because their opposites are tempting:

   - **Suppressions match against every *registered* rule, not the active set.** An
     annotation naming a rule that `--disable` turned off this run is correct and
     forward-looking, not a typo, and must not be reported as one.
   - **There is no "unused suppression" diagnostic.** It would fire every time a rule is
     narrowed or a finding genuinely fixed — precisely when the developer did the right thing.

   Suppressed findings are **counted in the report header** (`· 1 suppressed`). A suppressed
   finding is removed from the output, so that counter is the only place a reader learns it
   existed; without it a heavily suppressed scan would look identical to a clean one, which is
   the same false-clean §9 exists to prevent.

**Mechanisms 1 and 2 are enforced by `tests/anti-fp.test.ts` from the start** — not
bolted on once ten more rules exist. It asserts, for every rule in `RULES`: the
fixture pair exists and is non-empty, `docs/rules/<ID>.md` exists, the declared
severity respects `CONFIDENCE_CEILING[confidence]`, the id matches `MCP###`/`SKILL###`,
and the title is non-empty and doesn't end with a period. It also runs a scan
restricted to each rule against its own `vulnerable/` fixture (must find something)
and a scan with *every* registered rule against *every* `clean/` fixture (must find
nothing) — the cross-fixture check is what catches a new rule firing on another
rule's clean fixture, the most common way a false positive enters unnoticed. Both
fixture checks discover their subjects from the filesystem (`tests/fixtures/*/vulnerable`),
not a hardcoded id list, so a new rule is covered the moment its fixtures land.

**The corpus (mechanism 2) is live**, in `tests/corpus/`, and now covers every subject
kind the scanner has:

| Part | Contents | Rules it measures |
|---|---|---|
| `servers/` | `tools/list` captured from four official reference servers — 37 tools | MCP001–MCP006 |
| `skills/` | all 19 `SKILL.md` files from `anthropics/skills` | SKILL001–SKILL004, MCP001 |
| `source/` | 10 TypeScript files (~85 KB) of real reference-server implementation | MCP008 |
| `configs/` | 7 client configs — one committed `.mcp.json`, six vendor README install snippets | MCP007, MCP009 |

Everything is pinned to an exact version or commit and committed;
`scripts/capture-corpus.mjs` regenerates it by hand, and nothing is downloaded or
executed at test time. `anti-fp.test.ts` asserts a floor per subject kind as well as the
zero-high/critical contract — without `sourceFiles` MCP008 has no real input, without
`servers` neither do MCP007 and MCP009, and the contract would pass for those three by
never running them. See `tests/corpus/README.md`.

The corpus is deliberately **not finding-free**: five `medium` MCP007 findings stand
against the vendor install snippets, which really do say `npx -y <package>` with no
version pin. The contract is zero `high`/`critical`, not zero findings. A corpus that had
to be silent could only contain input too dull to test anything.

It earned its place on the first run, producing **13 `high` findings, every one of them
false** — nine from MCP004 against `@modelcontextprotocol/server-filesystem`, four from
SKILL004 against the `mcp-builder` skill. Both rules were narrowed (§7.4). This is the
mechanism working as designed and it is worth being precise about why: neither class was
reachable by writing more clean fixtures, because a fixture is written by the same person
who wrote the rule, in the same sitting, and encodes the same assumptions. A rule can only
be shown to be over-broad by input nobody wrote for it. That is the corpus's whole job, and
it is why a failure here is never resolved by adding an exception to the test — either the
rule narrows, or the entry leaves the corpus.

---

## 9. CLI

```
mcpscan [path]                       # default: '.'

  --format <fmt>      pretty | json | sarif | github | baseline   (default: pretty if TTY, json otherwise)
  --output <file>     write to a file instead of stdout
  --fail-on <sev>     critical | high | medium | low | none   (default: high)
  --rules <ids>       comma-separated list; run only these
  --disable <ids>     turn off specific rules
  --connect           starts the server and uses tools/list (runs the target's code — opt-in)
  --baseline <file>   ignores findings already present in the baseline
  --config <file>     default: mcpscan.config.json
  --no-color
  --quiet
```

Everything above is implemented except `--connect`, which is out of MVP scope (§7.1).

### 9.2 Precedence

**CLI flag > config file > built-in default**, without exception. A flag someone typed is a
decision made for this run and a file in the repository must never override it. The merge is
`resolveOptions()` in `src/config.ts`, kept pure and separately tested: an option whose default
is applied too early stops the config from ever being consulted, and nothing about the output
would show it.

### 9.3 `mcpscan.config.json`

```json
{ "version": 1, "failOn": "high", "rules": [], "disable": ["MCP007"], "format": "sarif", "baseline": "mcpscan-baseline.json" }
```

Two properties follow directly from §16.1 and §16.3, and are in the first version rather than
retrofitted:

- **`version` is required.** A wire format without one cannot be changed later without breaking
  every file already written.
- **An unrecognised key is exit 2, not a shrug.** The failure mode §16.1 lists for this file is
  "scan silently runs with defaults" — `"failon"` for `"failOn"` is exactly that, and nothing
  else in the run would ever mention it. Rejecting costs one clear error; accepting costs a
  wrong scan indefinitely.

A config file the user *named* and that is missing is exit 2; the default file simply not
existing is the normal case and means "no config". Rule ids are not validated here — `scan()`
already rejects an unknown id wherever it came from, and two validators for one thing drift.

### 9.4 Baseline

Adopting a scanner on an existing repository is the moment it gets used or gets deleted. A
first run on untouched code lights up, and a developer facing forty findings they did not
introduce either fixes all of them before merging anything or turns the scanner off. The
baseline is the third option: record what is already there, fail only on what is new.

Generated through the format machinery rather than a flag of its own — a baseline is a
rendering of the findings, which is what a format is:

```
mcpscan --format baseline --output mcpscan-baseline.json
mcpscan --baseline mcpscan-baseline.json
```

- **Entries match on the SARIF fingerprint** (`core/fingerprint.ts`), extracted so the baseline
  and `partialFingerprints` cannot develop two different notions of "the same finding". Since
  that fingerprint excludes the line number, a baseline does not go stale when an unrelated edit
  shifts a finding down the file.
- **The file is versioned and names its fingerprint scheme.** A baseline written under a future
  `mcpScan/v2` is detected and rejected rather than silently matching nothing.
- **It stores `ruleId`, `file` and `jsonPath` alongside each hash** so a reviewer can see what
  was accepted. A list of opaque hashes is unreviewable, and an unreviewable baseline is how
  findings quietly become permanent. It stores neither the message (not contract, §16.5) nor the
  line — both would churn the committed file for fields nothing matches on.
- **A baseline that fails to load is exit 2**, never "no baseline". Degrading would turn every
  accepted finding back on at once, which reads as the scanner having found new problems.
- Baseline is applied *after* suppressions, so a finding with a written justification is not also
  counted as untriaged backlog.

### 9.5 `--quiet`

Prints findings only: no header, no severity summary, and **nothing at all** when a successful
scan is clean. It affects `pretty` alone — silencing a machine-readable format would defeat the
purpose of asking for it.

The one thing it must never do is make "could not look" look like "clean" (§16.6), so an error
prints in full regardless. Silence is only ever allowed to mean clean.

**Exit codes** (stable contract — CI depends on this):

| Code | Meaning |
|---|---|
| 0 | No finding at the `--fail-on` level or above |
| 1 | Findings at the `--fail-on` level or above |
| 2 | Execution error — **"couldn't look"** |

Telling 1 from 2 matters: `1` means "found a problem", `2` means "couldn't look". A CI that treats both the same hides a broken scanner as if it were a clean repo.

**Every exit-2 condition** (closed list — the Phase 1 review showed almost all of them were silently returning 0):

| Condition | Why it's exit 2, not 0 |
|---|---|
| Path doesn't exist | Obvious |
| No active rule after `--rules`/`--disable` | A typo (`--rules MCP02`) turned off the scanner with no signal |
| Unknown rule ID in `--rules`/`--disable` | Same |
| Invalid value in `--fail-on` or `--format` | `--fail-on NONE` (uppercase) made `rank()` return `-1` and the threshold accept everything |
| **Zero subjects discovered** | Pointing at the wrong directory gave the same green checkmark as a genuinely clean scan |
| **A rule threw an exception** | A broken rule turned into an `info` finding; with `--fail-on high` CI stayed green. A bug in any rule turned into a silent false-clean. |
| **A named `--config` file is missing, malformed, wrongly versioned, or has an unrecognised key** | The scan would run with defaults while a file in the repository says otherwise, and nothing would report it (§16.1). |
| **A `--baseline` file is missing, malformed, or wrongly versioned** | Degrading to "no baseline" turns every already-accepted finding back on at once, which is indistinguishable from the scanner having found new problems. |

The report for a scan with zero subjects **must not** look visually identical to a clean scan. `stats` reports two distinct counts: files **scanned** and files that **produced** tools.

**An exit-2 run with `--format sarif --output <file>` still writes the SARIF file** — but one whose `runs[0].invocations[0].executionSuccessful` is `false`, not a document with empty `results` and no invocation metadata (§10). Silently skipping the write would be strictly worse than what it replaces: the workflow step would fail with no artifact at all, which at least does not risk being read as a clean result by anything downstream.

### 9.1 `pretty` output

Real output of `mcpscan tests/fixtures/MCP002/vulnerable --no-color` (exit 1):

```
mcpscan · 1 file(s) scanned · 1 with tools · 1 tool(s) · 0 skill(s)

CRITICAL  MCP002  Invisible Unicode character in tool definition
  tools.json:5:22  tools[0].description
  Tool "read_file" has 6 invisible character(s) in `description`: U+E0049 (tag character), U+E0067 (tag character), U+E006E (tag character), U+E006F (tag character), U+E0072 (tag character), U+E0065 (tag character).
  Fix: Remove the invisible characters. This text is read by the model and never shown to the user — invisible content here is a hidden instruction, not formatting.
  https://github.com/luked20/mcpscan/blob/main/docs/rules/MCP002.md

  1 critical
```

Output rules: severity first, a clickable location as `file:line:col`, `Fix:` always present, a link always present. No ASCII banner, no emoji, no spinner.

**Two counts in the header, not one.** `scanned` is how many files the scanner opened; `with tools` is how many produced something analyzable. A single count would confuse "I looked at 40 files and 1 had tools" with "I only looked at 1 file" — and that confusion is the difference between a good scan and a scan that didn't run.

---

## 10. SARIF

A priority since Phase 2 — it's what plugs into GitHub code scanning with no effort from the user.

- `runs[].tool.driver.rules[]` — one per registered rule, with `id`, `name`, `shortDescription`, `fullDescription`, `helpUri`, `defaultConfiguration.level`.
- `runs[].results[]` — `ruleId`, `level`, `message.text`, `locations[].physicalLocation` with `artifactLocation.uri` (relative, `/`) and `region` (`startLine`, `startColumn`, `endLine`, `endColumn`).
- `partialFingerprints["mcpScan/v1"]` = hash(ruleId + path + jsonPath + normalized evidence).
  **Without a stable fingerprint, GitHub reopens the same alert on every commit** and the user turns the tool off. The fingerprint **must not** include the line number — otherwise any edit above it generates a new alert.
- `runs[].invocations[]` — **exactly one** invocation object, on every run, always. `executionSuccessful` is `true` for exit 0/1 and `false` for exit 2 (§9). On failure, the invocation also carries `toolExecutionNotifications: [{ level: 'error', message: { text }, descriptor: { id: 'mcpscan/scan-failed' } }]` with the same error string the CLI writes to stderr. No `commandLine`, `arguments`, or `workingDirectory` — a SARIF file gets committed and shared, and absolute paths from a developer's machine are needless leakage.

  **Why this exists:** GitHub code scanning reconciles every SARIF upload against the previous one and *closes* alerts that were open before but are absent from the new upload. Before this field, an exit-2 run (bad path, zero subjects, a crashing rule) still produced a document with `results: []` and no invocation metadata — indistinguishable from a genuinely clean scan. GitHub would read that as "reanalyzed, found nothing" and close every previously-reported alert, while the CI job itself turned red. The scan failure and the security data would disagree: the job fails, but the Security tab goes quiet. `executionSuccessful: false` tells GitHub the run did not complete, so it does not treat an empty `results[]` as a clean bill of health. `executionSuccessful` is a **required** SARIF invocation property regardless — this closes a real gap, not just a defensive addition.

Severity → SARIF `level`: critical/high → `error`, medium → `warning`, low/info → `note`.

---

## 11. GitHub Action

`action.yml` at the root, for direct use as `uses: luked20/mcpscan@v1`:

```yaml
- uses: luked20/mcpscan@v1
  with:
    path: .
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpscan.sarif
```

The Action is a thin wrapper: it runs `npx mcpscan --format sarif --output mcpscan.sarif`. No new logic.

---

## 12. Stack

| Piece | Choice | Why |
|---|---|---|
| Language | TypeScript, ESM, Node ≥ 20 | npm/npx distribution is the channel |
| Tests | Vitest | Fast, native ESM, built-in snapshots |
| Build | tsup → single ESM bundle | `npx` on an unbundled package is slow; startup is UX |
| JSON w/ position | `jsonc-parser` | Zero deps, AST with offsets |
| YAML w/ position | `yaml` | CST with ranges |
| Glob | `tinyglobby` | Lightweight |
| CLI | `commander` | Standard, predictable |
| Color | `picocolors` | ~2 kB |

Target: **≤ 8 runtime dependencies**. Every dependency is attack surface in a security tool, and latency on `npx`.

---

## 13. File layout

```
src/
  cli/index.ts           # arg parsing, orchestration, sets the exit code
  core/types.ts          # IR (§5) — no logic
  core/location.ts       # offset -> line/col; builds SourceLocation
  core/engine.ts         # subjects x rules -> Finding[]; applies the confidence ceiling
  core/config.ts         # loads mcpscan.config.json, merges with flags
  core/suppress.ts       # parses mcpscan-disable-next-line
  collect/mcp-config.ts
  collect/mcp-manifest.ts
  collect/skill-md.ts
  collect/source.ts
  collect/index.ts       # discover(root) -> ScanTarget
  rules/index.ts         # registry (explicit array)
  rules/mcp/MCP001.ts ... rules/skill/SKILL004.ts
  rules/shared/patterns.ts   # shared injection regexes, ONE place only
  report/pretty.ts
  report/json.ts
  report/sarif.ts
  report/github.ts
tests/
  fixtures/<RULE_ID>/{vulnerable,clean}/
  corpus/                # real clean manifests, for FP regression
docs/
  rules/<RULE_ID>.md
action.yml
```

---

## 14. Known risks

| Risk | Mitigation |
|---|---|
| False positive destroys trust | §8: regression corpus + confidence ceiling + fixture pair |
| `--connect` runs malicious code | Opt-in, explicit warning, never on by default or in the Action |
| MCP manifest format evolves | Isolated collectors; rules depend only on the IR |
| Injection regex turns into cat-and-mouse | Accepted: the MVP catches the non-adversarial case (Snyk's 36.82% is mostly mistakes, not targeted attacks). Document the limitation in the README instead of pretending to have coverage. |
| Nobody installs it | Phase 2 (SARIF + Action) **before** rule #2 — distribution before depth |

---

## 15. Points that need verification before coding

- ~~**Official OWASP MCP Top 10 IDs.**~~ **Resolved on 2026-08-28:** list verified at <https://owasp.org/www-project-mcp-top-10/>, full mapping in §7.1. Relevant finding: "schema poisoning" and "tool shadowing" are not their own categories — they're sub-techniques of `MCP03:2025`. And `MCP09:2025 Shadow MCP Servers` ended up without a rule (§7.1).
- ~~**npm package name.**~~ **Resolved on 2026-08-28:** `mcp-scan` is taken (v2.0.6, Invariant Labs — a direct competing MCP scanner) and so is `mcp-scanner`. Chosen name: **`mcpscan`** (available). Binary `mcpscan`, directive `mcpscan-disable-next-line`, config `mcpscan.config.json`.
- ~~**Canonical `SKILL.md` format.**~~ **Resolved on 2026-08-28**, verified against 60 real installed SKILL.md files. Findings that change the implementation:
  - `name` and `description` are present in 100% of them; **`allowed-tools` doesn't appear in any top-level skill** — only in plugin skills. Confirms SKILL003 should return `[]` when the field is absent: absence isn't a false declaration.
  - The real format of `allowed-tools` is a **YAML list**, not a comma-separated string. `toArray()` accepts both.
  - Entries are **scoped**: `Bash(git *)`, `Agent(name)`, `Workflow(x)`. SKILL003's `split('(')[0]` normalizes this. Accepted consequence: a skill that declares `Bash(ls *)` and runs `curl` in the body is **not** detected, because `Bash` is on record as declared. Deliberate under-detection — err toward false negative, not false positive.
  - There are also `disallowed-tools`, `user-invocable`, and `disable-model-invocation`. None affect the MVP.

---

## 16. Public contract

A decision becomes expensive to change at exactly the moment its output becomes **someone else's data**.

While something lives only in this repository, changing it costs a `sed`. The moment it leaves — published to npm, written into someone's SARIF, pasted into a workflow, typed into a suppression comment in a third party's source — changing it stops being a refactor and becomes a breaking change. Some of these do not look like breaking changes at all, which is what makes them dangerous.

This section is the inventory. Nothing here changes without a major version bump.

### 16.1 What becomes someone else's data

| Surface | Where it ends up | Cost of changing it later |
|---|---|---|
| **Rule IDs** (`MCP004`, `SKILL002`) | `mcpscan-disable-next-line MCP004` comments in user source; GitHub alert history | Suppressions silently stop matching and the finding **reappears**. The user did nothing wrong and gets no warning. |
| **Per-rule severity** | Their `--fail-on high` in CI | Raising `medium` → `high` turns every user's build red with no change on their side. Does not look like a breaking change; is one. |
| **Fingerprint composition** | GitHub's code-scanning alert database | Every alert for every user reopens at once. |
| **Exit codes 0/1/2** | Conditionals in their workflows | Silent and catastrophic — a workflow that treated 2 as 0 would hide a broken scanner. |
| **Suppression directive syntax** | Their source files | Every suppression stops working simultaneously. |
| **Config file name and schema** (`mcpscan.config.json`) | Their repository | Scan silently runs with defaults. |
| **Package name and binary name** (`mcpscan`) | `package.json`, workflows, muscle memory | — |
| **SARIF `rule.id` values** | GitHub keys alerts on `ruleId` | Same as rule IDs. |
| **User-facing language** (English) | Rule names rendered in GitHub's Security tab | Every alert becomes unreadable noise for most of the audience. |

### 16.2 Versioning policy

| Change | Bump |
|---|---|
| New rule added | minor |
| Existing rule made **more precise** (fewer false positives, same ID and severity) | patch |
| Existing rule made **broader** (detects more, may fire where it did not) | minor, and call it out in the changelog |
| Rule severity changed | **major** |
| Rule ID renamed or removed | **major** |
| Exit code semantics changed | **major** |
| Fingerprint composition changed | **major** — and only via a new fingerprint key (see 16.3) |
| Suppression syntax or config schema changed | **major** |
| Default `--fail-on` changed | **major** |

A rule getting *more precise* is a patch because it can only reduce findings — a green build stays green. A rule getting *broader* can turn a green build red, so it is never a patch even though it feels like an improvement.

### 16.3 Version every wire format from day one

**Worked example, taken while it was still free.** A finding's fingerprint includes its
`location.jsonPath`. Until now `loc()` took a joined string that callers built by
concatenating `origin.jsonPath`, and re-splitting it by `.` was wrong for any key that
contains a dot — `mcpServers.awslabs.mysql-mcp-server.args` parsed as four segments,
resolved to nothing, and reported the whole server object. Real: found on the first scan of
`awslabs/mcp`, where PyPI-style server names are ordinary. `loc()` now takes path
*segments*, which makes the ambiguity unrepresentable.

Fixing it necessarily changes `jsonPath` — and therefore the fingerprint — for exactly the
findings that were wrong. On a published tool that is a §16.2 major-bump event and a wave of
reopened GitHub alerts. At version `0.0.0`, with nothing on npm and no baseline in anyone's
repository, it costs nothing. That asymmetry is the whole reason this section exists: the
window to fix an identity bug closes the moment the identity becomes someone else's data.

The SARIF fingerprint key is `mcpScan/v1`, not `mcpScan`. That single decision means a future change to fingerprint composition can ship as `mcpScan/v2` alongside `v1`, letting GitHub migrate alerts instead of reopening all of them at once.

Apply the same reasoning to anything else that crosses the boundary: the config file carries a `version` field, and any future baseline file format does too. A wire format without a version field cannot be changed without breaking whoever already wrote one.

### 16.4 Pre-flight, before anything leaves the machine

Ran before Task 1; all three found a problem:

- [x] **Package name available on npm.** `mcp-scan` is taken — v2.0.6, Invariant Labs, a **direct competitor** doing approximately what this spec describes. `mcp-scanner` also taken. Adopted `mcpscan`.
- [x] **OWASP MCP Top 10 IDs verified against the published list.** The labels originally invented for the `owasp` field (`Excessive Agency`, `Prompt Injection`, `Credential Exposure`) do not exist in that taxonomy. See §7.1.
- [x] **`SKILL.md` frontmatter verified against real skills**, not documentation. `allowed-tools` turned out to be optional, YAML-list shaped, and scope-qualified — see §15.

Before the first publish, additionally:

- [ ] SARIF validates against the official schema (`@microsoft/sarif-multitool validate`) with zero warnings — GitHub rejects invalid SARIF silently.
- [ ] Every registered rule has `docs/rules/<ID>.md` live at its `helpUri`; a broken help link in a security report costs more trust than a missing one.
- [ ] The GitHub Action's example workflow has been run once end to end, with the SARIF actually appearing in the Security tab.
- [ ] `npx <name>@<version> --help` works from an empty directory outside this repo.

### 16.5 What is deliberately NOT contract

Free to change at any time, and stated here so nobody treats them as stable: the exact wording of `message` and `remediation` text, the `pretty` output layout, the ordering of findings beyond the documented sort keys, internal module structure, and the IR types in §5. Users should key on `ruleId` and `severity`, never on message text — and the docs should say so.

### 16.6 The invariant every new layer must re-learn

One defect reappeared four times in this codebase, once per layer added. Each time it looked like a new bug. It was the same invariant failing to propagate into a new piece.

| Layer | How it expressed itself | Severity |
|---|---|---|
| `scan()` | A file passed as the argument scanned nothing and exited 0 | silent |
| Rule engine | A rule that threw became an `info` finding; CI stayed green | silent |
| Rule selection | `--rules MCP999` disabled the scanner with no signal | silent |
| **SARIF artifact** | A failed scan uploaded an empty document, **closing previously-open GitHub alerts** | **destructive** |
| Collectors | A `SKILL.md` or `.mcp.json` that would not parse was dropped; a valid one beside it reported "No problems found" | silent |

A new layer is born unable to tell *"I looked and it is clean"* from *"I could not look."* It has to be taught, every time.

The fifth entry arrived after this section was written, which is the point: the collectors were added, they had their own tests, those tests passed, and the invariant still did not come along. Note the distinction the fix turns on — a `.json` that merely is not a manifest stays silent, because nothing claimed it was one; a file whose *name* declares what it is (`SKILL.md`, `.mcp.json`) and will not parse is reported. The question is not "did this fail" but "did something claim to be scannable and then not get scanned."

**Therefore, a mandatory review question for every layer, format, or output added from here on:**

> Can this layer express "I could not look", or does it only know how to say "nothing found"?

Ask it of every new reporter, every new collector, every new transport, every new artifact that leaves the machine. A local test does not catch this, because each layer's own tests are written by someone who is thinking about that layer's happy path.

Note the severity ordering the table reveals, which is the right one to reason with: **destructive beats silent beats noisy.** The first three defects merely failed to report. The fourth deleted data that already existed in someone else's repository. A tool that erases prior findings is worse than a tool that crashes, because a crash is visible and an erasure looks like progress.
