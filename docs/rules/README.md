# Rule documentation

Every implemented detection rule has a doc here: the risk it addresses, a
vulnerable example, a clean example, and how to fix (and, where applicable,
suppress) a finding. Each finding's `helpUri` links directly to the matching
file.

| ID | Name | Severity | OWASP MCP Top 10 |
|---|---|---|---|
| [MCP002](MCP002.md) | Invisible Unicode character in tool definition | critical | MCP03:2025 – Tool Poisoning |

More rules are planned — see [`docs/SPEC.md`](../SPEC.md) §7 for the full
catalog and what's still to come. The top-level [README](../../README.md)
has the quick-start and CI usage.
