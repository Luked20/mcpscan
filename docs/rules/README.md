# Rule documentation

Every implemented detection rule has a doc here: the risk it addresses, a
vulnerable example, a clean example, and how to fix (and, where applicable,
suppress) a finding. Each finding's `helpUri` links directly to the matching
file.

| ID | Name | Severity | OWASP MCP Top 10 |
|---|---|---|---|
| [MCP001](MCP001.md) | Model-directed instruction in tool description | critical | MCP03:2025 – Tool Poisoning |
| [MCP002](MCP002.md) | Invisible Unicode character in tool definition | critical | MCP03:2025 – Tool Poisoning |
| [MCP003](MCP003.md) | Model-directed instruction inside inputSchema | critical | MCP03:2025 – Tool Poisoning |
| [MCP004](MCP004.md) | Unconstrained path parameter in a file tool | high | MCP02:2025 – Privilege Escalation via Scope Creep |
| [MCP005](MCP005.md) | Unconstrained command parameter | high | MCP05:2025 – Command Injection & Execution |
| [MCP007](MCP007.md) | Unpinned MCP server provenance | medium | MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering |
| [MCP009](MCP009.md) | Credential hardcoded in MCP server configuration | high | MCP01:2025 – Token Mismanagement & Secret Exposure |
| [SKILL002](SKILL002.md) | Model-directed instruction in skill description | critical | MCP10:2025 – Context Injection & Over-Sharing |

More rules are planned — see [`docs/SPEC.md`](../SPEC.md) §7 for the full
catalog and what's still to come. The top-level [README](../../README.md)
has the quick-start and CI usage.
