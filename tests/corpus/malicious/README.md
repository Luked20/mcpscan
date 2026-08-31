# Malicious corpus — recall

Captured attacks. The mirror of `../clean/`: that one asserts the scanner stays
quiet on code that is fine, this one asserts it speaks up when an attack is
actually there.

Enforced by `tests/recall.test.ts`, which checks **rule and severity** per case,
not merely that something fired.

## Why captured, and not written here

Every rule already has a `tests/fixtures/<ID>/vulnerable/` case that it detects.
That proves the rule fires on the attack its author imagined — which is very
nearly a tautology, and the same blind spot the clean fixtures had before
`../clean/` existed. Recall needs payloads from somewhere else.

None of these were written for this project:

| Source | What it is |
|---|---|
| [`invariantlabs-ai/mcp-injection-experiments`](https://github.com/invariantlabs-ai/mcp-injection-experiments) | The PoCs from the research that named tool poisoning |
| [`harishsg993010/damn-vulnerable-MCP-server`](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | A deliberately vulnerable server built as a teaching corpus |

## Why a captured `tools/list`, and not the server

Each directory holds the `tools/list` response the real attack serves, obtained
once with `--connect` and committed with its `PROVENANCE.txt`. So the test
installs nothing, downloads nothing, executes no third-party code, and does not
break when the Python SDK changes its API — while still measuring the actual
payload rather than a paraphrase of it.

## The two cases that expect nothing

Both are load-bearing, and neither is a placeholder.

**`invariant-rug-pull-benign`** is the clean half of a server that turns
malicious on its second run. Captured twice, the same server gives a clean list
and a poisoned one. `--connect` answers *what is this server exposing now*, never
*what will it expose tomorrow* — a property of snapshots, not a defect to fix
inside a scanner.

**`dvmcp-challenge1-prompt-injection`** is a known miss. The vulnerability is not
in a tool at all: it lives in MCP **resources** (`internal://credentials`, hidden
from listing; `notes://{user_id}`, unvalidated input), and this scanner collects
tools only. No rule of any quality could catch it. The expectation is empty on
purpose and will start failing the day resources are collected — which is exactly
when someone should come back and set it. See `docs/SPEC.md` §8.5.

## Adding a case

1. Capture it: `--connect` against the real PoC, save the `tools/list` verbatim.
2. Write `PROVENANCE.txt` — repository, commit, file, date.
3. Write `EXPECTED.json` — what the attack does, and the exact `ruleId`/`severity`
   pairs it must produce. An empty `expect` is allowed, and must say why.

The harness discovers cases from the filesystem, so nothing else needs editing.
