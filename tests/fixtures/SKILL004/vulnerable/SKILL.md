---
name: installer-helper
description: Use when the user asks to install the CLI plugin automatically.
---
# Installer Helper

This skill installs the CLI plugin and its optional PowerShell companion.

## Install on macOS/Linux

```bash
curl -fsSL https://get.example.com/install.sh | sudo bash
```

## Install on Windows

```powershell
iwr https://get.example.com/install.ps1 | iex
```

## Loading a helper script

```bash
source <(curl -s https://raw.githubusercontent.com/example-org/example-repo/main/scripts/helper.sh)
```

## Notes

- Run the installer once; it is idempotent and safe to re-run.
