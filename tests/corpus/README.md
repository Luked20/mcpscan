# Regression corpus

Real, third-party, known-clean MCP servers and agent skills. The rule is
simple and is enforced by `tests/anti-fp.test.ts`:

> **A scan of this directory with every registered rule must produce zero
> `high` and zero `critical` findings.**

`docs/SPEC.md` §8.2 calls this mechanism 2 of false-positive control. A rule
that breaks this test does not ship.

## Why this exists on top of the clean fixtures

`tests/fixtures/<ID>/clean/` is written by whoever wrote the rule, at the
time they wrote it. It proves the rule doesn't fire on the near-misses that
author *thought of*. It cannot prove the rule isn't over-broad in some way
they didn't — that is exactly the blind spot, and no amount of care while
writing the fixture closes it.

Real manifests can. On its first run this corpus produced **13 `high`
findings, all of them false**:

| Rule | Findings | On | What was actually wrong |
|---|---|---|---|
| MCP004 | 9 | `@modelcontextprotocol/server-filesystem` | A file tool must take a path. The rule fired on every correctly built file server, including one that declares its allow-list in its own tool descriptions and enforces it in the handler. Fixed by the manifest-wide scope exemption — `docs/rules/MCP004.md`. |
| SKILL004 | 4 | `mcp-builder` skill | All four were the MCP SDK's `README.md` fetched from `main` for the model to *read*. A document is not code; the rule is `remote-code-fetch`. Fixed by excluding documentation extensions — `docs/rules/SKILL004.md`. |

Both are recorded in `docs/SPEC.md` §7.4. Neither would have been found by
writing more fixtures by hand.

## What is in here

### `servers/` — captured `tools/list` output

| Directory | Package | Tools |
|---|---|---|
| `memory/` | `@modelcontextprotocol/server-memory` | 9 |
| `sequential-thinking/` | `@modelcontextprotocol/server-sequential-thinking` | 1 |
| `everything/` | `@modelcontextprotocol/server-everything` | 13 |
| `filesystem/` | `@modelcontextprotocol/server-filesystem` | 14 |

Each `tools.json` is `{ "name": <the server's own reported name>, "tools":
[...] }` — the server's verbatim `tools/list` response under the root `name`
it reported at `initialize`, which is the shape this scanner's manifest
collector reads. Each directory carries a `PROVENANCE.txt` naming the exact
package version and capture date.

The reference servers build their tool schemas at runtime (zod / pydantic),
so there is no literal JSON in their source to copy. The only faithful way to
get their real schemas is to ask them, which is what
`scripts/capture-corpus.mjs` does.

### `skills/` — real `SKILL.md` files

All 19 skills from [`anthropics/skills`](https://github.com/anthropics/skills),
downloaded verbatim at a pinned commit (see `skills/PROVENANCE.txt`). Nothing
is executed for these. They are long, prose-heavy, and full of shell
commands, tool references, and imperative instructions — which is precisely
the input that makes SKILL001–SKILL004 and MCP001 hard to keep precise.

## Regenerating

```bash
node scripts/capture-corpus.mjs            # everything
node scripts/capture-corpus.mjs memory     # one server
node scripts/capture-corpus.mjs skills     # just the skills
```

Run by hand, rarely, and never as part of `npm test` — the tests read only
what is committed here. Regenerating **starts the server packages**, which is
third-party code execution; that is why it is a separate manual script. Every
entry is pinned to an exact version or commit, so regenerating does not
silently change what the test measures.

## When this test fails

Do not add an exception, an allowlist, or a baseline. There are exactly two
honest outcomes, and the point of the corpus is to force the choice:

1. **The rule is over-broad.** Narrow it, add the case to that rule's clean
   fixtures, and record the trade-off in `docs/SPEC.md` §7.4 and the rule's
   own doc.
2. **This entry is not actually clean.** Then it does not belong in the
   corpus — remove it, and write down what it does that a clean server
   doesn't.

## What is not covered yet

- **MCP client configs.** No `.mcp.json` / `claude_desktop_config.json` from
  a real repository, so MCP007 and MCP009 are measured only by their own
  fixtures. The natural next addition.
- **Server source code.** No real MCP server `.ts`/`.js` implementation, so
  MCP008 is measured only by its own fixtures.
- **Servers needing credentials.** Everything here starts with no API key,
  which biases the set toward small, local, official servers.
