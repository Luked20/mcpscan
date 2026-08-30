# SKILL003 — Skill uses a capability it does not declare

**Severity:** high · **Confidence:** medium · **OWASP MCP:** `MCP02:2025 – Privilege Escalation via Scope Creep`

## The risk

`allowed-tools` in a skill's frontmatter is the one place a reviewer can see, at a glance, what a skill is permitted to touch — network, filesystem reads, filesystem writes — without reading the entire body line by line. When the body actually runs a shell command, reads a file, or writes a file that the declaration doesn't mention, the declaration undersells the skill's real reach. A reviewer who trusts `allowed-tools` as a summary walks away thinking the skill is narrower than it is.

This is a **risk-surface** rule (see `docs/SPEC.md` §7.3), not a payload rule: it doesn't detect malicious text, it detects a mismatch between what's declared and what's used. That mismatch is often just an incomplete declaration, not an attack — which is why this rule is `medium` confidence and capped at `high` severity, never `critical`.

## Vulnerable example

    ---
    name: env-bootstrapper
    description: Use when the user asks to bootstrap a new local development environment.
    allowed-tools:
      - Read
    ---
    # Environment Bootstrapper

    ```bash
    curl -fsSL https://example.com/setup-deps.sh -o setup-deps.sh
    ```

    ```bash
    echo "bootstrap complete" >> progress.log
    ```

The declaration says this skill only reads. The body also runs `curl` (needs `Bash`) and writes a file via `>>` (needs `Write`) — neither is declared.

## Clean example

    ---
    name: release-helper
    description: Use when the user asks to prepare a release branch and validate its configuration.
    allowed-tools:
      - Bash(git *)
      - Read
      - Write
    ---
    # Release Helper

    ```bash
    git status
    ```

    ```bash
    cat package.json
    ```

    ```bash
    echo "Prepared release notes" > release-notes.md
    ```

Every capability the body actually uses — running `git` (`Bash`), reading `package.json` (`Read`), writing `release-notes.md` (`Write`) — is declared.

## What this rule does NOT flag

- **A skill with no `allowed-tools` field at all.** This is the single most important exception, and it is not a guess: verified against 60 real installed `SKILL.md` files, `allowed-tools` appeared in **none** of the top-level skills — only in plugin skills (`docs/SPEC.md` §15). Absence is the overwhelmingly common case, and it means *no declaration was made*, which is a different thing from *an incomplete declaration was made*. A rule that treated absence as under-declaration would fire on nearly every skill that exists. If you want this rule to actually check your skill, add an `allowed-tools` list — that's what turns it on.
- **`allowed-tools` present but empty.** Same reasoning as above — an empty list is treated the same as no declaration.
- **A capability that's already covered by a broader scope.** `Bash(ls *)` in the declaration counts as `Bash` being declared, full stop. A skill that declares `Bash(ls *)` and then runs `curl` in the body is **not** flagged, because `Bash` is on record. This is deliberate under-detection (`docs/SPEC.md` §7.4 / §15): scoping a `Bash` grant to a specific command is a bash-level concern this rule doesn't model, and erring toward the false negative here is the safer failure mode for a self-serve scanner.
- **A command word that only appears in prose**, e.g. "This skill replaces the old curl-based workflow." Nothing runs unless it's inside a fenced code block or inline code span.
- **A command word inside a JSON or YAML example fence**, e.g. a config sample with a field literally named `curl`. Detection requires the line to *start* with the command word (the shape of an actual invocation), not just contain it.
- **`>` that is not a redirect**, even inside a fenced code block. Three shapes are excluded, and all three came from a scan of monday's MCP plugin where **every one of the five** SKILL003 findings was this detector reading prose as a shell redirect:

  | Line | What the `>` actually is |
  |---|---|
  | `> Action 1: Notify [deal owner]` | a markdown blockquote |
  | `- Active pipeline: $<total>K across <N> deals` | the close of a `<total>` placeholder |
  | `Synced <N> meetings to <M> deals.` | the same, twice |

  So: a line starting with `>` is a quote; a `>` that closes a `<…>` with no whitespace inside is a placeholder or an HTML tag; and the redirect target must be a **path or a file with an extension** (`out/log`, `report.txt`, `/dev/null`), not a bare word. `> phone` and `> Action` are not files.

  Every `>` on a line is checked, not just the first — on `echo "synced <N> items" > out/sync.log` the first closes a placeholder and the second is real.
- **The body of the skill for anything other than these three signals.** Hidden instructions are SKILL001's job; description-field injection is SKILL002's.

## Known accepted false negative

- **A redirect to a bare word** — `echo done > outfile`, with no extension and no
  path separator. Requiring one is what makes "writes a file" mean writing a
  file rather than matching any `>` followed by a word, and the alternative was
  five false positives out of five on the first real skill set this rule met.

## How to fix

Add the missing tool to `allowed-tools`, or remove the instruction that needs it if the skill doesn't actually require that capability.

```diff
 allowed-tools:
   - Read
+  - Bash
+  - Write
```

## How to suppress

```
// mcpscan-disable-next-line SKILL003 -- reason
```

A reason after `--` is required. A suppression with no reason is ignored and reported instead.

> Suppressions are specified but **not yet implemented** — see the project README.

See [MCPSCAN001](MCPSCAN001.md).
