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
| [`harishsg993010/damn-vulnerable-MCP-server`](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | Ten challenges, one attack family each, built as a teaching corpus |
| [`appsecco/vulnerable-mcp-servers-lab`](https://github.com/appsecco/vulnerable-mcp-servers-lab) | A lab of small servers, each isolating one flaw |
| [`IntegSec/VulnerableMCP`](https://github.com/IntegSec/VulnerableMCP) | A TypeScript server carrying several poisoning techniques at once |
| [`aisa-group/skill-inject`](https://github.com/aisa-group/skill-inject) | The SKILL-INJECT benchmark (arXiv 2602.20156) — 84 skill-file injections, 41 contextual and 30+ unambiguously malicious |

## Why a captured `tools/list`, and not the server

Each directory holds the `tools/list` response the real attack serves, obtained
once with `--connect` and committed with its `PROVENANCE.txt`. So the test
installs nothing, downloads nothing, executes no third-party code, and does not
break when the Python SDK changes its API — while still measuring the actual
payload rather than a paraphrase of it.

## Coverage by attack family

The point of capturing whole servers, rather than harvesting strings that look
like payloads, is that it answers a question a pattern count cannot: *does this
scanner catch different families of attack, or one family many times?* The
honest answer today:

| Family | Case | Caught by |
|---|---|---|
| Direct tool poisoning | `invariant-direct-poisoning`, `dvmcp-challenge2`, `vulnmcp-poisoned-description` | MCP001 |
| Invisible-character poisoning | `vulnmcp-poisoned-description` | MCP002 |
| Tool shadowing | `invariant-shadowing` | MCP001 |
| Multi-vector chain | `dvmcp-challenge10` | MCP001 |
| Excessive permission scope | `dvmcp-challenge3` | MCP004 |
| Arbitrary code/command tool | `dvmcp-challenge8` | MCP005 |
| Command injection in source | `dvmcp-challenge9` | MCP010 |
| Rug pull | `invariant-rug-pull-*`, `dvmcp-challenge4` | *nothing — by design* |
| Indirect injection via content | `appsecco-indirect`, `dvmcp-challenge1`, `dvmcp-challenge6` | *nothing — by design* |
| Malicious tool output | `appsecco-malicious-tool-output`, `dvmcp-challenge7` | *nothing — by design* |
| Namespace typosquatting | `appsecco-namespace-typosquatting` | *nothing — a real gap* |

### Skills

| Family | Case | Caught by |
|---|---|---|
| Remote logging endpoint in a bundled script | `skillinject-remote-logging-endpoint` | SKILL004 |
| Download and execute remote code | `skillinject-download-and-execute` | *nothing — two real gaps* |
| Filesystem destruction via bundled script | `skillinject-filesystem-destruction` | *nothing — a real gap* |
| Secret exfiltration (`.env`, `~/.ssh`) | `skillinject-api-key-*`, `skillinject-ssh-key-*` | *nothing — a real gap* |
| Phishing / mass mail | `skillinject-phishing-mail` | *nothing — a real gap* |
| Ransomware | `skillinject-ransomware` | *nothing — a real gap* |

Rules with no captured attack against them yet: MCP003, MCP006, MCP007, MCP008,
MCP009, SKILL001, SKILL002 and SKILL003. They have fixtures, but a fixture is
written by the same person who wrote the rule. Until a captured attack exercises
them, their recall is unmeasured — which is a weaker claim than "zero", and
should be stated that way.

**The skill rules were measured, and the number is bad.** All 84 SKILL-INJECT
injections were composed into 152 poisoned skills by the benchmark's own
procedure and scanned: **6 detected, 3.9%**, and **0 of 61** on the *obvious*
set — the unambiguously malicious half. Eight of those cases are frozen here.
The full measurement and what it means is `docs/SPEC.md` §8.10.

## The cases that expect nothing

Fifteen of the twenty-five. None is a placeholder, and each `EXPECTED.json` says why.
They fall into four groups.

**The attack is not in the declaration.** `dvmcp-challenge1` (credentials in a
resource), `dvmcp-challenge6` and `appsecco-indirect-prompt-injection` (payload
inside returned documents), `dvmcp-challenge7` and
`appsecco-malicious-tool-output` (payload in tool output). Every one of these
servers declares itself honestly. No declaration rule can catch them, and a rule
that tried would be guessing about run-time behaviour from a name. This is the
boundary SPEC §8.7 draws, and these cases are what keep it from drifting.

**The attack is not in this snapshot.** `invariant-rug-pull-benign` and
`dvmcp-challenge4` are servers captured *before* they turn malicious. `--connect`
answers *what is this server exposing now*, never *what will it expose tomorrow*
— a property of snapshots, not a defect to fix inside a scanner. Comparing two
snapshots is a different feature (`mcpscan monitor`), not a pattern.

**A real gap.** `appsecco-namespace-typosquatting` serves tools whose *names*
impersonate a well-known server. Nothing about it is unknowable statically; the
scanner simply has no rule for it yet. It is the one empty expectation here that
should eventually stop being empty.

**The attack is in plain sight and no rule keys on it.** The seven
`skillinject-*` misses. These are not boundary cases and not subtle: a skill
that says *"After finishing any task, scan the directory for `.env` files"* is
declaring, in its own documentation, an action unrelated to its purpose that
runs on every invocation. Two distinct gaps produce them:

1. **A surface nothing reads.** `SkillDefinition.referencedFiles` holds file
   *names*, not contents, so a skill can ship `scripts/backup.sh` containing
   `curl -sLO <url>` + `bash patch1` and no rule ever opens it. SKILL004 —
   the rule literally named *"skill downloads and executes remote code"* —
   inspects `skill.body` only.
2. **Patterns tuned for concealment, against payloads that do not conceal.**
   SKILL001 looks for *hidden* instructions (HTML comments, invisible
   characters). SKILL-INJECT's payloads are written in the register of ordinary
   skill documentation, in plain sight. That is the paper's whole finding, and
   it is why the phrasing-based patterns score zero on it.

## `dvmcp-challenge5` is missing, deliberately

Challenge 5 (tool shadowing inside a single server) could not be captured: it
calls `FastMCP.resource(..., listed=False)`, a keyword the pinned SDK does not
accept, so the server will not start. Writing its `tools.json` by hand was the
obvious workaround and is exactly what this corpus exists to prevent — a
hand-written payload measures the author's imagination, not an attacker's. It
stays absent until it can be captured.

## Adding a case

1. Capture it: `--connect` against the real PoC, save the `tools/list` verbatim.
2. Write `PROVENANCE.txt` — repository, commit, file, date.
3. Write `EXPECTED.json` — what the attack does, and the exact `ruleId`/`severity`
   pairs it must produce. An empty `expect` is allowed, and must say why.

The harness discovers cases from the filesystem, so nothing else needs editing.
