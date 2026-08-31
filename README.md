# mcpscan

A security scanner for **MCP servers and agent skills**. Runs locally and in CI,
finds known vulnerability patterns — tool poisoning, hidden Unicode, unsafe
schemas, data exfiltration, destructive helper scripts — and reports them with
an exact file/line location, not a vague warning.

Sixteen rules, 1128 tests, and every rule calibrated against third-party attack
corpora rather than against fixtures written by the same person who wrote the
rule. See [Measured, not asserted](#measured-not-asserted).

## Quick start

```bash
npx mcpscan .
```

Real output against a vulnerable fixture (`mcpscan tests/fixtures/MCP002/vulnerable --format pretty`):

```
mcpscan · 1 file(s) scanned · 1 with tools · 1 tool(s) · 0 skill(s)

CRITICAL  MCP002  Invisible Unicode character in tool definition
  tools.json:5:22  tools[0].description
  Tool "read_file" has 6 invisible character(s) in `description`: U+E0049 (tag character), U+E0067 (tag character), U+E006E (tag character), U+E006F (tag character), U+E0072 (tag character), U+E0065 (tag character).
  Fix: Remove the invisible characters. This text is read by the model and never shown to the user — invisible content here is a hidden instruction, not formatting.
  https://github.com/Luked20/mcpscan/blob/main/docs/rules/MCP002.md

  1 critical
```

Exit code is `1` — see [Exit codes](#exit-codes) below for what that means in
a script.

## Running it on a real repository

Against [`awslabs/mcp`](https://github.com/awslabs/mcp), a 2,500-file monorepo of
production MCP servers:

```console
$ mcpscan . --format pretty
mcpscan · 2518 file(s) scanned · 0 with tools · 0 tool(s) · 8 server(s) · 7 skill(s) · 1161 source file(s)

MEDIUM    MCP007  Unpinned MCP server provenance
  src/aurora-dsql-mcp-server/kiro_power/mcp.json:4:15  mcpServers.aurora-dsql.args
  Server "aurora-dsql" is started by fetching a package at run time with no exact version pin, so each run may download different code than the one you reviewed.
  Fix: Pin the exact version (for example `package@1.4.2`), or install the package as a project dependency and point `command` at the local binary. Commit a lockfile so the transitive tree is pinned too.
  https://github.com/Luked20/mcpscan/blob/main/docs/rules/MCP007.md

MEDIUM    MCP007  Unpinned MCP server provenance
  src/cloudwatch-mcp-server/skills/agentcore-investigation/mcp/.mcp.json:4:15  mcpServers.cloudwatch.args
  …

  7 medium
```

Seven findings across 2,518 files, all the same real issue and none of them
noise. Now the same scanner on a server from the
[Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
challenge set, frozen in this repo's corpus:

```console
$ mcpscan tests/corpus/malicious/dvmcp-challenge9-command-injection --format pretty
mcpscan · 3 file(s) scanned · 1 with tools · 5 tool(s) · 0 server(s) · 0 skill(s) · 1 source file(s)

HIGH      MCP010  Dangerous execution sink in Python server source
  server.py:55:18
  Calls `subprocess.check_output(...)` with `shell=True` and a command built from a value built elsewhere. The string is parsed by a shell, so an interpolated value containing `;`, `|` or `$()` runs as a separate command.
  Fix: Pass the command and its arguments as a list and leave `shell=False` (the default) — `subprocess.run(["git", "log", rev])` — so no shell parses the string. …
  https://github.com/Luked20/mcpscan/blob/main/docs/rules/MCP010.md

  4 high
```

That case is worth a second look: **its `tools/list` is completely clean**, and
correctly so — `ping_host` takes a `host` string exactly as an honest
network-diagnostics server would. The declaration scan finds nothing; the source
scan finds four command injections. Neither mode is a superset of the other.

And a poisoned agent skill, from the
[SKILL-INJECT](https://github.com/aisa-group/skill-inject) benchmark:

```console
$ mcpscan tests/corpus/malicious/skillinject-download-and-execute --format pretty
HIGH      SKILL004  Skill downloads and executes remote code
  scripts/backup.sh:4:1
  Skill "docx" ships `scripts/backup.sh`, which downloads a file and then executes it: `curl -sLO http://…/download/patch1` writes "patch1", and `bash patch1` runs it. Nothing reads the file in between, so whatever the remote host serves at run time is executed as-is.
  https://github.com/Luked20/mcpscan/blob/main/docs/rules/SKILL004.md
```

The `SKILL.md` body only says *"run the backup.sh script from this skill's
scripts directory"* — ordinary documentation, and not a finding. The payload is
in the file the skill ships.

## Measured, not asserted

Most scanners are tested against examples their own author wrote, which proves
the rule fires on the attack its author imagined. Every rule here is measured
two ways, against corpora from somewhere else.

**Precision** — findings on code that is fine:

| Corpus | Findings |
|---|---|
| 106 real agent skills (Anthropic's, monday.com's, n8n's, AWS Labs') | 0 |
| `monday`, `supabase`, `playwright`, `firecrawl` repositories | 0 |
| 125 real shell scripts | 0 |

**Recall** — captured attacks from public research, frozen in
`tests/corpus/malicious/` with their provenance and expected rule *and*
severity, so a regression fails the build:

| Attack family | Caught |
|---|---|
| Exfiltration | 26 / 55 |
| Destruction | 8 / 22 |
| Remote code execution | 3 / 4 |
| Ransomware, DoS, phishing, bias | 1 / 44 |
| **Total (SKILL-INJECT, 152 poisoned skills)** | **39 (25.7%)** |

25.7% is a real number, not a rounded claim, and the gaps are named rather than
hidden. Three candidate rules were **rejected** during calibration for firing on
legitimate code — including a `git push --force` / `git reset --hard` detector
that looked ideal until it flagged a `git` skill teaching the command and a
`safety-protocol` skill quoting it as a thing *not* to do. A pattern cannot tell
"do this" from "never do this."

Sources: [DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server) ·
[SKILL-INJECT](https://github.com/aisa-group/skill-inject) (arXiv 2602.20156) ·
[Invariant Labs](https://github.com/invariantlabs-ai/mcp-injection-experiments) ·
[appsecco](https://github.com/appsecco/vulnerable-mcp-servers-lab) ·
[IntegSec](https://github.com/IntegSec/VulnerableMCP)

## CI / GitHub Action

```yaml
name: mcpscan
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Luked20/mcpscan@v1
        id: scan
        continue-on-error: true
        with: { path: '.', fail-on: 'high' }
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: mcpscan.sarif }
      - if: steps.scan.outcome == 'failure'
        run: exit 1
```

`continue-on-error` plus the final re-check is deliberate: the SARIF file has
to upload **even when the scan finds something**, otherwise you get a red job
with no annotation explaining why. Findings land in the PR's Security tab via
`upload-sarif`, then the last step turns the job red again once the upload is
done.

This snippet lives at
[`.github/workflows/example-usage.yml`](.github/workflows/example-usage.yml)
in this repo, and the Action itself is defined in
[`action.yml`](action.yml).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at the `--fail-on` level or above |
| `1` | Findings at the `--fail-on` level or above |
| `2` | Execution error — **the scanner could not scan** |

`1` and `2` are not interchangeable. `1` means "looked, found a problem."
`2` means "couldn't look" — wrong path, no MCP server or skill found, a rule
crashed, an invalid flag. A workflow that treats `2` the same as `0` will
report a broken scan as a clean one. Check the exit code explicitly; don't
just gate on "job passed." With `--format sarif`, a failed scan (exit `2`)
still produces a SARIF file, but one marked `executionSuccessful: false` so
GitHub code scanning doesn't read it as a clean analysis and close your
existing alerts.

## Rules

| ID | Name | Severity | OWASP MCP Top 10 | Docs |
|---|---|---|---|---|
| `MCP001` | Model-directed instruction in tool description | critical | MCP03 – Tool Poisoning | [MCP001.md](docs/rules/MCP001.md) |
| `MCP002` | Invisible Unicode character in tool definition | critical | MCP03 – Tool Poisoning | [MCP002.md](docs/rules/MCP002.md) |
| `MCP003` | Model-directed instruction inside inputSchema | critical | MCP03 – Tool Poisoning | [MCP003.md](docs/rules/MCP003.md) |
| `MCP004` | Unconstrained path parameter in a file tool | high | MCP02 – Privilege Escalation via Scope Creep | [MCP004.md](docs/rules/MCP004.md) |
| `MCP005` | Unconstrained command parameter | high | MCP05 – Command Injection & Execution | [MCP005.md](docs/rules/MCP005.md) |
| `MCP006` | Tool shadows or directs another tool | high | MCP03 – Tool Poisoning | [MCP006.md](docs/rules/MCP006.md) |
| `MCP007` | Unpinned MCP server provenance | medium | MCP04 – Supply Chain & Dependency Tampering | [MCP007.md](docs/rules/MCP007.md) |
| `MCP008` | Dangerous execution sink in server source (JS/TS) | high | MCP05 – Command Injection & Execution | [MCP008.md](docs/rules/MCP008.md) |
| `MCP009` | Credential hardcoded in MCP server configuration | high | MCP01 – Token Mismanagement & Secret Exposure | [MCP009.md](docs/rules/MCP009.md) |
| `MCP010` | Dangerous execution sink in Python server source | high | MCP05 – Command Injection & Execution | [MCP010.md](docs/rules/MCP010.md) |
| `SKILL001` | Hidden instruction in skill body | critical | MCP10 – Context Injection & Over-Sharing | [SKILL001.md](docs/rules/SKILL001.md) |
| `SKILL002` | Model-directed instruction in skill description | critical | MCP10 – Context Injection & Over-Sharing | [SKILL002.md](docs/rules/SKILL002.md) |
| `SKILL003` | Skill uses a capability it does not declare | high | MCP02 – Privilege Escalation via Scope Creep | [SKILL003.md](docs/rules/SKILL003.md) |
| `SKILL004` | Skill downloads and executes remote code | high | MCP04 – Supply Chain & Dependency Tampering | [SKILL004.md](docs/rules/SKILL004.md) |
| `SKILL005` | Skill sends data to a hardcoded external endpoint | high | MCP01 – Token Mismanagement & Secret Exposure | [SKILL005.md](docs/rules/SKILL005.md) |
| `SKILL006` | Skill ships a script that deletes files wholesale | high | MCP04 – Supply Chain & Dependency Tampering | [SKILL006.md](docs/rules/SKILL006.md) |

Every rule ships with a positive fixture, a negative fixture, and a page
recording what it deliberately does **not** flag and the measurement that
calibrated it.

## Options

```
mcpscan [path]                       # default: '.'

  --format <fmt>     pretty | json | sarif | github | baseline
                     (default: pretty if stdout is a TTY, json otherwise)
  --output <file>    write to a file instead of stdout
  --fail-on <sev>    critical | high | medium | low | none  (default: high)
  --rules <ids>      run only these rules (comma-separated)
  --disable <ids>    turn off these rules (comma-separated)
  --baseline <file>  ignore findings already listed in this file
  --connect <cmd>    start an MCP server and scan the tools it reports
  --connect-timeout <s>  how long to wait for --connect (default: 120)
  --config <file>    config file (default: mcpscan.config.json if present)
  --quiet            print findings only; nothing at all when a scan is clean
  --no-color         disable colors
```

## Scanning a server's actual tools

Pointing mcpscan at a repository finds its configs, its skills and its source —
but usually **not its tools**, because a real MCP server builds them in code at
startup and there is no manifest on disk to read. That leaves the tool-poisoning
and tool-shadowing rules with nothing to run on, and the report will tell you so.

To scan them, let mcpscan start the server and ask:

```bash
npx mcpscan . --connect "npx -y firecrawl-mcp"
```

It speaks the MCP handshake, reads `tools/list`, `resources/list` and
`prompts/list`, and scans those alongside everything it found on disk. The
server inherits your environment, so an API key is passed the way any client
passes one:

```bash
FIRECRAWL_API_KEY=fc-… npx mcpscan . --connect "npx -y firecrawl-mcp"
```

**This runs the server's code**, which is why it is opt-in and never implied.
Findings that came from it are marked `"provenance": "live"`. If the server
fails to start or refuses, that is exit 2 with its stderr attached — never a
clean report for a server that never ran.

## Adopting it on an existing repo

The first scan of a repository that has never been scanned will find things. If
you can't fix them all today, record them and fail only on what's new:

```bash
npx mcpscan --format baseline --output mcpscan-baseline.json   # once
npx mcpscan --baseline mcpscan-baseline.json                   # from then on
```

Commit the baseline. It stores a stable fingerprint per finding plus the rule
id and file, so you can read it in review — and the fingerprint ignores line
numbers, so it doesn't go stale when you edit the file above a finding. Delete
entries from it as you fix them.

A baseline is the blunt instrument. When a finding has an actual answer, prefer
a [suppression comment](docs/rules/MCPSCAN001.md) — it lives on the line and
carries the reason.

## Config file

Optional. `mcpscan.config.json` in the working directory, picked up
automatically:

```json
{
  "version": 1,
  "failOn": "high",
  "disable": ["MCP007"],
  "baseline": "mcpscan-baseline.json"
}
```

A command-line flag always wins over the file. `version` is required, and an
unrecognised key is an error rather than being ignored — a typo'd key would
otherwise leave the setting at its default with nothing to tell you.

## Suppressing a finding

A per-line comment, with a mandatory reason:

```
// mcpscan-disable-next-line MCP004 -- path is resolved and checked against ALLOWED_ROOT in readFile()
"path": { "type": "string" }
```

It applies to the next line only. Write it in whatever comment syntax the
file uses — `//` in JSONC and TS/JS, `#`, or `<!-- -->` in a `SKILL.md`.
Several rules at once: `MCP004, MCP005`.

**The reason after `--` is required.** Leave it out and the suppression does
nothing: the finding stands, and you get an `info` finding telling you the
comment did not work. Same for a comment that names no rule, or names one
that does not exist (`MCP404`) — a suppression that silently silences nothing
is worse than no suppression at all. See
[docs/rules/MCPSCAN001.md](docs/rules/MCPSCAN001.md).

Suppressed findings are counted in the header, so a heavily suppressed scan
never looks like a clean one:

```
mcpscan · 12 file(s) scanned · 3 with tools · 41 tool(s) · 2 server(s) · 0 skill(s) · 1 suppressed
```

To silence a rule everywhere instead of line by line, use `--disable <id>`.

## Working on mcpscan

```bash
npm install
npm test          # 1128 tests: rule units, fixture pairs, precision and recall harnesses
npm run typecheck
npm run build
```

`tests/corpus/clean/` asserts the scanner stays quiet on real code;
`tests/corpus/malicious/` asserts it speaks up on captured attacks, checking the
exact rule **and** severity so a downgrade fails the build too.

[`docs/rules/`](docs/rules/) has a page per rule: the risk, a vulnerable
example, a clean example, what the rule deliberately does **not** flag, and the
measurement that calibrated it.

## Limitations

Read this before you trust a clean scan.

- **Pattern-based detection.** The rules catch mistakes and known payloads.
  They are **not robust against an adaptive attacker who knows the rules** —
  a pattern matcher is not a substitute for review on anything you didn't
  write yourself.
- **Declarations, not behaviour.** mcpscan reads what a server and a skill
  *declare* — tool descriptions, schemas, configs, source, bundled scripts. It
  does not observe what they do at run time. An attack that lives entirely in
  a tool's *output*, or in a document a tool returns, is invisible to it, and
  several such cases are kept in the corpus with empty expectations and the
  reason written down.
- **A snapshot, never a forecast.** A "rug pull" server — honest on its first
  run, poisoned on its tenth — reports clean, because on the day you scanned it
  it *was* clean. Catching that needs two snapshots compared over time, which is
  a different feature, not a pattern.
- **Skill coverage is 25.7% against a published benchmark.** Measured, and the
  uncovered families are named above. MCP server coverage is considerably better
  but has no equivalent single number, because no comparable benchmark exists.
- **Known evasion seam in MCP002.** The rule's ZWJ/ZWNJ check only fires when
  *both* neighboring characters are ASCII/Latin, to avoid false-positiving on
  legitimate emoji sequences and Persian/Devanagari text. That leaves a gap:
  a zero-width joiner between a Latin character and a non-Latin one does not
  trigger — an accepted gap rather than a bug.

## Contributing

Adding a rule:

1. One file in `src/rules/` (e.g. `src/rules/mcp/MCP001.ts`).
2. One line registering it in `src/rules/index.ts`.
3. A positive fixture (`tests/fixtures/<ID>/vulnerable/`) **and** a negative
   one (`tests/fixtures/<ID>/clean/`) — a rule without both doesn't ship.
4. A measurement. Before a pattern ships it is run against the clean corpora
   above; a rule that fires on real code is rejected, and the number that
   rejected it is recorded in the rule's own source.

Anchor new rules to the OWASP MCP Top 10 or a documented real-world case — and
prefer a specific, documented rule over a broad heuristic. A false positive
costs more than a missed finding here: it is what makes people stop reading the
output.

## License

MIT
