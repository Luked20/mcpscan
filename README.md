# mcpscan

A security scanner for MCP servers and agent skills. Runs locally and in CI,
finds known vulnerability patterns — tool poisoning, hidden Unicode, unsafe
schemas — before they ship, and reports them with an exact file/line
location, not a vague warning.

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
  https://github.com/luked20/mcpscan/blob/main/docs/rules/MCP002.md

  1 critical
```

Exit code is `1` — see [Exit codes](#exit-codes) below for what that means in
a script.

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
      - uses: luked20/mcpscan@v1
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
| `MCP001` | Model-directed instruction in tool description | critical | [MCP03:2025 – Tool Poisoning](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP001.md](docs/rules/MCP001.md) |
| `MCP002` | Invisible Unicode character in tool definition | critical | [MCP03:2025 – Tool Poisoning](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP002.md](docs/rules/MCP002.md) |
| `MCP003` | Model-directed instruction inside inputSchema | critical | [MCP03:2025 – Tool Poisoning](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP003.md](docs/rules/MCP003.md) |
| `MCP004` | Unconstrained path parameter in a file tool | high | [MCP02:2025 – Privilege Escalation via Scope Creep](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP004.md](docs/rules/MCP004.md) |
| `MCP005` | Unconstrained command parameter | high | [MCP05:2025 – Command Injection & Execution](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP005.md](docs/rules/MCP005.md) |
| `MCP006` | Tool shadows or directs another tool | high | [MCP03:2025 – Tool Poisoning](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP006.md](docs/rules/MCP006.md) |
| `MCP007` | Unpinned MCP server provenance | medium | [MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP007.md](docs/rules/MCP007.md) |
| `MCP008` | Dangerous execution sink in server source | high | [MCP05:2025 – Command Injection & Execution](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP008.md](docs/rules/MCP008.md) |
| `MCP009` | Credential hardcoded in MCP server configuration | high | [MCP01:2025 – Token Mismanagement & Secret Exposure](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/MCP009.md](docs/rules/MCP009.md) |
| `SKILL001` | Hidden instruction in skill body | critical | [MCP10:2025 – Context Injection & Over-Sharing](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/SKILL001.md](docs/rules/SKILL001.md) |
| `SKILL002` | Model-directed instruction in skill description | critical | [MCP10:2025 – Context Injection & Over-Sharing](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/SKILL002.md](docs/rules/SKILL002.md) |
| `SKILL003` | Skill uses a capability it does not declare | high | [MCP02:2025 – Privilege Escalation via Scope Creep](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/SKILL003.md](docs/rules/SKILL003.md) |
| `SKILL004` | Skill downloads and executes remote code | high | [MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering](https://owasp.org/www-project-mcp-top-10/) | [docs/rules/SKILL004.md](docs/rules/SKILL004.md) |

Only these thirteen rules are implemented so far — the full MVP catalog from
`docs/SPEC.md` §7. More may be added later; see that section for the
rationale behind the ones that already exist.

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

It speaks the MCP handshake, reads `tools/list`, and scans those tools alongside
everything it found on disk. The server inherits your environment, so an API key
is passed the way any client passes one:

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

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the map of the repository: what
each folder does and how the pieces connect. [docs/SPEC.md](docs/SPEC.md) has
the reasoning behind the decisions, and [docs/rules/](docs/rules/README.md) has
a page per rule.

## Limitations

Read this before you trust a clean scan.

- **Pattern-based detection.** The rules catch mistakes and known payloads.
  They are **not robust against an adaptive attacker who knows the rules** —
  a pattern matcher is not a substitute for review on anything you didn't
  write yourself.
- **Thirteen rules are implemented** (`MCP001`–`MCP009`, `SKILL001`–
  `SKILL004`) — the full MVP catalog in `docs/SPEC.md` §7. A clean scan
  today means "no invisible Unicode, no model-directed instruction found in
  the tool description, input schema, or skill frontmatter/body, no
  unconstrained path/command parameter in a file or execution tool, no tool
  name collision or redirecting description across servers, no unpinned or
  plaintext server provenance, no dangerous execution sink pattern in server
  source, no hardcoded credential in an MCP config, no undeclared capability
  used in a skill body, and no remote-code-fetch pattern in a skill body,"
  not "this server or skill is safe."
- **Static analysis only.** `mcpscan` never starts your MCP server or calls
  `tools/list`. Live introspection (`--connect`) is deliberately left out of
  the MVP because it would mean executing untrusted code to scan it.
- **Known evasion seam in MCP002.** The rule's ZWJ/ZWNJ check only fires when
  *both* neighboring characters are ASCII/Latin, to avoid false-positiving on
  legitimate emoji sequences and Persian/Devanagari text. That leaves a gap:
  a zero-width joiner between a Latin character and a non-Latin one does not
  trigger. See `docs/SPEC.md` §7.2 for the full policy table and why it's an
  accepted gap rather than a bug.

## Contributing

Adding a rule:

1. One file in `src/rules/` (e.g. `src/rules/mcp/MCP001.ts`).
2. One line registering it in `src/rules/index.ts`.
3. A positive fixture (`tests/fixtures/<ID>/vulnerable/`) **and** a negative
   one (`tests/fixtures/<ID>/clean/`) — a rule without both doesn't ship.
4. `docs/rules/<ID>.md` describing the risk, a vulnerable example, a clean
   example, and how to fix it.

Anchor new rules to the OWASP MCP Top 10 or a documented real-world case
(Snyk's agent-skill audit, a known MCP CVE) — see `docs/SPEC.md` for the
rationale behind the rules that already exist.
