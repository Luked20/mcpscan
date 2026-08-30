# SKILL004 — Skill downloads and executes remote code

**Severity:** high · **Confidence:** high · **OWASP MCP:** `MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering`

## The risk

A skill that pipes a downloaded script straight into a shell or PowerShell interpreter — or that pulls source from a `raw.githubusercontent.com` URL pinned to a branch rather than a commit — executes whatever the remote host serves *at run time*, not whatever a reviewer looked at when the skill was written or approved. The content behind the URL can change after review, silently, with no diff for anyone to see. This is the same class of risk MCP007 flags in MCP server configuration; here it's the skill body instead of a server's launch command.

This is a **payload** rule (see `docs/SPEC.md` §7.3): the three patterns it matches have no legitimate excuse to appear together the way they do. Confidence is `high`.

## Vulnerable example

    ```bash
    curl -fsSL https://get.example.com/install.sh | sudo bash
    ```

    ```powershell
    iwr https://get.example.com/install.ps1 | iex
    ```

    ```bash
    source <(curl -s https://raw.githubusercontent.com/example-org/example-repo/main/scripts/helper.sh)
    ```

All three fire independently: pipe-to-shell, pipe-to-PowerShell, and an unpinned `raw.githubusercontent.com` fetch (the ref is `main`, a branch name, not a commit SHA).

## Clean example

    ```bash
    curl -o data.json https://api.example.com/data
    ```

    ```bash
    curl -s https://api.example.com/status | jq '.state'
    ```

    ```
    https://raw.githubusercontent.com/example-org/example-repo/da39a3ee5e6b4b0d3255bfef95601890afd80709/scripts/helper.sh
    ```

The first command downloads to a file rather than executing it. The second pipes into `jq`, a read-only filter, not a shell. The third is pinned to a full 40-character commit SHA, so the content it fetches can't change out from under a reviewer.

## What this rule does NOT flag

- **A download that isn't piped into an interpreter**, e.g. `curl -o data.json https://api.example.com/data`. Fetching data is not this rule's concern; executing it unreviewed is.
- **A pipe into anything other than a shell or PowerShell**, e.g. `curl ... | jq '.state'`. Only `sh`/`bash`/`zsh`/`ksh` (with an optional `sudo`) and `iex`/`Invoke-Expression` count as executing the piped content.
- **`cat file.txt | sh`.** This is a local file, not a network fetch — the pipe-to-shell pattern only fires when a `curl` or `wget` invocation feeds the pipe, because the risk this rule targets is specifically *remote* code changing after review. A local script being piped into a shell is a different (and differently-scoped) risk; SKILL003 is the rule that reasons about a skill's declared capabilities.
- **A `raw.githubusercontent.com` URL pinned to a full 40-character commit SHA.** That content cannot change without the URL changing too.
- **A documentation file** — a URL whose path ends in `.md`, `.markdown`, `.txt`, `.rst`, or `.adoc` (a query string or fragment is ignored when deciding). This rule is *remote code fetch*: the risk it names is a skill running code whose content can change after review. A `.md` file is read, not run. The regression corpus (`docs/SPEC.md` §8.2) found this the expensive way — the official `mcp-builder` skill produced four `high` findings, every one of them the MCP SDK's own `README.md` fetched from `main` for the model to read. Remote *text* pulled into a model's context is a real risk, but it is a prompt-injection risk, which is SKILL001 and SKILL002's subject; filed under this rule it was simply the wrong finding.

## How to fix

Pin the source by commit SHA instead of a branch or tag, or download the script to a file, review it, and execute the verified copy. For a published release, verify the checksum instead of trusting the URL alone.

```diff
- curl -fsSL https://get.example.com/install.sh | sudo bash
+ curl -fsSL https://get.example.com/install.sh -o install.sh
+ # review install.sh, then:
+ sudo bash install.sh
```

```diff
- https://raw.githubusercontent.com/example-org/example-repo/main/scripts/helper.sh
+ https://raw.githubusercontent.com/example-org/example-repo/da39a3ee5e6b4b0d3255bfef95601890afd80709/scripts/helper.sh
```

## How to suppress

```
// mcpscan-disable-next-line SKILL004 -- reason
```

A reason after `--` is required. A suppression with no reason is ignored and reported instead.

> Suppressions are specified but **not yet implemented** — see the project README.

See [MCPSCAN001](MCPSCAN001.md).
