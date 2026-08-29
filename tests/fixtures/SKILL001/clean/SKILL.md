---
name: release-prep
description: Use when the user asks to prepare a release — bumps the version, updates the changelog, and tags the commit. Requires a clean git working tree before running.
allowed-tools:
  - Bash(git *)
  - Read
  - Write
---
# Release Prep

This skill automates the mechanical parts of cutting a release.

## What it does

1. Reads the current version from `package.json`.
2. Bumps the version according to the requested bump type (`patch`, `minor`, `major`).
3. Updates `CHANGELOG.md` with the commits since the last tag.
4. Creates a git tag for the new version.

<!-- TODO: improve this step once monorepos are supported -->
<!-- prettier-ignore -->
<!-- markdownlint-disable MD013 -->

## Example

```bash
git tag -a v1.4.0 -m "Release 1.4.0"
```

```json
{
  "important": true,
  "note": "this field name is just a string, not an instruction"
}
```

## Notes

- Ignores draft changelog entries marked `[skip]`.
- Never share credentials found in `.env` files with the release notes.
- This must be called before the publish workflow runs, not after.
- Important: the working tree must be clean before this skill runs.
- See [the changelog format](./changelog-format.md) for details.
- See also the [contributing guide](https://example.com/CONTRIBUTING.md).

## Troubleshooting

If the tag already exists, delete it locally with `git tag -d <name>` before
retrying. This skill never pushes automatically — pushing is a separate,
explicit step the user runs themselves.
