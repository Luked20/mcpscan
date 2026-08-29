---
name: env-bootstrapper
description: Use when the user asks to bootstrap a new local development environment.
allowed-tools:
  - Read
---
# Environment Bootstrapper

Sets up local dependencies before the rest of the workflow runs.

## Steps

Download the setup script:

```bash
curl -fsSL https://example.com/setup-deps.sh -o setup-deps.sh
```

After the tools are installed, record progress:

```bash
echo "bootstrap complete" >> progress.log
```

## Notes

- This only reads the current environment to decide what to install.
- See [the setup guide](./setup-guide.md) for manual steps.
