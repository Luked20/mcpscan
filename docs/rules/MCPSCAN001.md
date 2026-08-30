# MCPSCAN001 — Malformed suppression comment

**Severity:** info · **Confidence:** high
**OWASP MCP:** none — this is not a vulnerability

## What this is

Not a detection rule. Every other id in this directory describes something
that might be wrong with the *scanned* server; this one describes something
wrong with an **annotation in it**. That is why it sits in its own
`MCPSCAN###` namespace, is not in the rule registry, and cannot be selected
with `--rules` or turned off with `--disable`.

It fires when a suppression comment exists but cannot be honoured.

## Suppressing a finding

```
// mcpscan-disable-next-line MCP004 -- path is resolved and checked against ALLOWED_ROOT in readFile()
"path": { "type": "string" }
```

The comment applies to **the next line only**. The marker is recognised
inside any comment syntax the scanned files use — `//` in JSONC and TS/JS,
`#`, `<!-- -->` in `SKILL.md`, and block comments — because a manifest, a
skill, and a server implementation are three different languages and the
annotation should read the same in all of them.

Several rules at once, comma- or space-separated:

```
// mcpscan-disable-next-line MCP004, MCP005 -- both reviewed in PR #214
```

## The reason is mandatory, and that is the whole point

Everything after `--` is the justification, and without it the suppression
**does not take effect**. The finding stands, and this diagnostic is
reported next to it.

That is deliberate. A scanner a developer cannot silence case by case gets
silenced wholesale instead — `--disable MCP004` for the entire repository, or
the CI step deleted — and both are a total loss next to one annotated line.
But a suppression with no written reason is indistinguishable, six months
later, from a finding someone silenced because they did not feel like dealing
with it. Requiring the sentence is what keeps the escape hatch from becoming
the way the tool's output decays into noise everyone scrolls past.

## When it fires

| Comment | Why it does not work |
|---|---|
| `// mcpscan-disable-next-line MCP004` | No `--` and no reason. |
| `// mcpscan-disable-next-line MCP004 --` | Separator present, reason empty. |
| `<!-- mcpscan-disable-next-line MCP004 -->` | Same: the `--` here is the closing `-->`, not a separator. The terminator is stripped before the reason is parsed, precisely so this does *not* silently pass as a reason of `>`. |
| `// mcpscan-disable-next-line -- trust me` | Names no rule. A blanket suppression would also silence every rule written after it, which is broader than anyone needs and broader than `docs/SPEC.md` §8.3 defines. |
| `// mcpscan-disable-next-line MCP404 -- reviewed` | Names a rule that does not exist. This is the silent-typo failure: it looks like protection and provides none. The diagnostic lists the valid ids. |

A comment naming both a real and an unknown rule (`MCP004, MCP404`) still
suppresses `MCP004` — and still reports the typo.

A comment naming a rule that `--disable` turned off for this run is **not** a
defect. Suppressions are matched against every registered rule, not the
active set, so an annotation stays correct when the rule is switched back on.

## What it does NOT flag

- **A suppression that suppresses nothing** because the next line has no
  finding. There is no "unused suppression" diagnostic. Reporting one would
  fire every time a rule is narrowed or a finding is genuinely fixed, which
  is exactly when the developer has done the right thing.
- **A mention of the marker that is not starting a comment.** The marker has
  to be the first thing on the line apart from whitespace and comment
  punctuation (`//`, `#`, `/*`, ` * `, `<!--`). So a string literal
  (`const MARKER = 'mcpscan-disable-next-line'`), a JSON value
  (`"note": "mcpscan-disable-next-line ..."`), and prose that names it in
  backticks are all ignored. This is not a nicety: without it, this scanner's
  own source — which necessarily writes the marker in strings and doc
  comments — produced three of these findings on a self-scan.

  The remaining edge is a **markdown bullet**: `- mcpscan-disable-next-line
  MCP004 -- reason` in a `SKILL.md` is indistinguishable, by prefix alone,
  from a real comment, because `-` is also comment punctuation. Documenting a
  suppression inside a skill body will be read as using one.

## Suppressed findings are counted, never silent

The report header carries the number:

```
mcpscan · 1 file(s) scanned · 1 with tools · 4 tool(s) · 0 server(s) · 0 skill(s) · 1 suppressed
```

A suppressed finding is removed from the report, so this counter is the only
place a reader learns it existed. Without it, a heavily suppressed scan would
look exactly like a clean one — the same failure `docs/SPEC.md` §9 describes
for a scan that found no files at all.

## Can this be suppressed?

No. `MCPSCAN001` is not in the rule registry, so
`// mcpscan-disable-next-line MCPSCAN001 -- ...` names an unknown rule and
reports itself. Suppressing the diagnostic that tells you your suppressions
do not work would defeat the mechanism.
