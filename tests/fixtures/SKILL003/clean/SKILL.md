---
name: release-helper
description: Use when the user asks to prepare a release branch and validate its configuration.
allowed-tools:
  - Bash(git *)
  - Read
  - Write
---
# Release Helper

This skill validates the release configuration and prepares the branch.

## What it does

1. Reads `package.json` for the current version.
2. Validates the config shown below against the schema.
3. Writes a summary to `release-notes.md`.

## Example commands

```bash
git status
git tag -a v1.4.0 -m "Release 1.4.0"
```

```bash
cat package.json
```

```bash
echo "Prepared release notes" > release-notes.md
```

## Config example (not executed)

```json
{
  "curl": "this key just happens to be named curl, it is not a command",
  "note": "no shell command runs here"
}
```

```yaml
tools:
  - name: curl
    kind: reference-only
```

## Notes

- This skill replaces the old curl-based workflow that used to run manually.
- The check passes when count > threshold is satisfied — no code involved.

> This blockquote uses the same character source-control diffs use to mark
> quoted text, not a shell redirect.

- See [the changelog format](./changelog-format.md) for details.

## Troubleshooting

If the tag already exists, delete it locally with `git tag -d <name>` before
retrying. This skill never pushes automatically — pushing is a separate,
explicit step the user runs themselves.

## Report template

These lines come from monday's MCP plugin, where every one of them was read as
a shell redirect. `<...>` is placeholder syntax and `>` at the start of a line
is a quote; neither writes anything.

```
> When: Stage → Won
> Action 1: Notify [deal owner]
> Action 2: Move item to Closed Won group
```

```
- Active pipeline: $<total>K across <N> deals
- Closing this week: <N> deals, $<value>K
Synced <N> meetings to <M> deals. <K> unmatched, <L> contacts created.
<count> example items added per board.
```
