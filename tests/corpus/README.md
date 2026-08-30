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

28 skills from two vendors, downloaded verbatim at pinned commits (see
`skills/PROVENANCE.txt`). Nothing is executed for these.

| Source | Count | Prefix |
|---|---|---|
| [`anthropics/skills`](https://github.com/anthropics/skills) | 19 | none |
| [`mondaycom/mcp`](https://github.com/mondaycom/mcp) (the `monday-crm` plugin) | 9 | `monday-` |

Two vendors on purpose. The anthropics set is large but written by one
organisation in one house style, which is a narrow sample for prose-heavy
rules. The monday set is a second voice, and it earned its place immediately:
**all five** SKILL003 findings on it were false, one detector reading markdown
blockquotes and `<placeholder>` syntax as shell redirects. They are long, prose-heavy, and full of shell
commands, tool references, and imperative instructions — which is precisely
the input that makes SKILL001–SKILL004 and MCP001 hard to keep precise.

### `source/` — real MCP server implementations

10 TypeScript files (~85 KB) from `modelcontextprotocol/servers`, downloaded
verbatim at a pinned commit:

| Directory | Files |
|---|---|
| `filesystem/` | `index.ts`, `lib.ts`, `path-utils.ts`, `path-validation.ts`, `roots-utils.ts` |
| `git/`, `fetch/`, `time/` | `server.py` — the Python half of the reference servers |
| `memory/` | `index.ts` |
| `sequential-thinking/` | `index.ts`, `lib.ts`, `version.ts` |
| `everything/` | `index.ts` |

This is MCP008's and MCP010's only real-world input. Its own fixtures are code written to
trip it, which can show it fires when it should and can never show it firing
on code nobody wrote to trip it. `filesystem` is the largest entry on
purpose: a server whose entire job is touching the filesystem on paths an
agent supplies is the shape a sink rule is most likely to over-match on.

These files are excluded from `tsconfig.json` and from the invisible-character
check in `anti-fp.test.ts`. They are someone else's code, held here as data;
the only way to make them satisfy this project's source hygiene would be to
edit them, which destroys the one property that makes them worth having.

### `configs/` — real MCP client configuration

What MCP007 (unpinned provenance) and MCP009 (credentials in config) get
measured against. Two provenances, kept apart because they are not equally
strong evidence — each directory's `PROVENANCE.txt` says which it is:

| Entry | Provenance | What it exercises |
|---|---|---|
| `mcp-docs/` | **A committed `.mcp.json`**, verbatim, from `modelcontextprotocol/servers` | An `https` remote server |
| `filesystem-npx/` | README install snippet | `npx -y` with no version pin |
| `filesystem-docker/` | README install snippet | `docker run` with bind mounts |
| `memory/` | README install snippet | An `env` block (a path, not a secret) |
| `everything/` | README install snippet | `npx -y` with no version pin |
| `firecrawl/` | README install snippet, third-party | A placeholder API key in `env` |
| `tavily/` | README install snippet, third-party | A placeholder API key inside the command's URL |

Only one entry is a config found in the wild. That is not for lack of
looking: a client config is normally per-developer and gitignored, and a
survey of fifteen popular MCP repositories turned up exactly two committed
`.mcp.json` files, both identical and both a single `https` entry.

The rest are install snippets published in each server's own README —
extracted verbatim, selected by a substring rather than a position so the
choice is legible and does not silently move if the document is reordered.
They were not found in the wild, but they are not invented either: they are
the exact JSON the vendor instructs users to paste into their client config,
which is what real config files end up containing.

**This part of the corpus is not finding-free, and should not be.** Five
`medium` MCP007 findings stand against it, one per vendor snippet that says
`npx -y <package>` with no version pin. Those are true positives: the
official install instructions really do fetch whatever the registry serves at
run time. The contract is zero `high`/`critical`, not zero findings — a
corpus that had to be silent would be a corpus that could only contain
uninteresting input.

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

- **Servers needing credentials.** Every captured server starts with no API
  key, which biases `servers/` toward small, local, official ones. The
  third-party entries in `configs/` partly offset this, but only for config.
- **Server source beyond TypeScript and Python.** Those are the two languages
  the rules cover (MCP008 and MCP010); anything else is neither collected nor
  scanned.
- **A genuinely adversarial corpus.** Everything here is known-clean by
  construction. It measures false positives and says nothing about false
  negatives — for which the honest answer stays `docs/SPEC.md` §14.

## What it surfaced beyond false positives

Not what this corpus is built to find, but worth recording where it was
found: **MCP007 does not cover `docker run`.** The `filesystem-docker`
snippet launches `mcp/filesystem` with no tag, which resolves to `:latest` —
the same "you get whatever the registry serves today" risk the rule already
reports for `npx -y`, through a package manager it does not check. Recorded
as an accepted false negative in `docs/SPEC.md` §7.4 and
`docs/rules/MCP007.md`; closing it means parsing `docker run` argv well
enough to tell the image from its flags, which is a rule change, not a corpus
change.
