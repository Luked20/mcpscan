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

Only these three rules are implemented so far. More are planned — see
[`docs/SPEC.md`](docs/SPEC.md) §7 for the full catalog (schema poisoning,
tool shadowing, command-injection surfaces, unpinned server provenance,
secrets in config, and the agent-skill equivalents).

## Options

```
mcpscan [path]                       # default: '.'

  --format <fmt>     pretty | json | sarif | github
                     (default: pretty if stdout is a TTY, json otherwise)
  --output <file>    write to a file instead of stdout
  --fail-on <sev>    critical | high | medium | low | none  (default: high)
  --rules <ids>      run only these rules (comma-separated)
  --disable <ids>    turn off these rules (comma-separated)
  --no-color         disable colors
```

## Suppressing a finding

The plan is a per-line suppression comment with a mandatory reason:

```
// mcpscan-disable-next-line MCP002 -- reason
```

**This is not implemented yet.** It's scoped for a later phase. Right now the
only way to silence a rule is `--disable <id>` for the whole run — there is
no way to suppress a single finding in place.

## Limitations

Read this before you trust a clean scan.

- **Pattern-based detection.** The rules catch mistakes and known payloads.
  They are **not robust against an adaptive attacker who knows the rules** —
  a pattern matcher is not a substitute for review on anything you didn't
  write yourself.
- **Only three rules are implemented so far** (`MCP001`, `MCP002`, `MCP003`). The rest of
  the OWASP MCP Top 10 categories in `docs/SPEC.md` §7 are not covered yet. A
  clean scan today means "no invisible Unicode and no model-directed
  instruction found in the tool description or its input schema," not "this
  server is safe."
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
