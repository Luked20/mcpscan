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
| [MCP006](MCP006.md) | Tool shadows or directs another tool | high | MCP03:2025 – Tool Poisoning |
| [MCP007](MCP007.md) | Unpinned MCP server provenance | medium | MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering |
| [MCP008](MCP008.md) | Dangerous execution sink in server source | high | MCP05:2025 – Command Injection & Execution |
| [MCP009](MCP009.md) | Credential hardcoded in MCP server configuration | high | MCP01:2025 – Token Mismanagement & Secret Exposure |
| [MCP010](MCP010.md) | Dangerous execution sink in Python server source | high | MCP05:2025 – Command Injection & Execution |
| [SKILL001](SKILL001.md) | Hidden instruction in skill body | critical | MCP10:2025 – Context Injection & Over-Sharing |
| [SKILL002](SKILL002.md) | Model-directed instruction in skill description | critical | MCP10:2025 – Context Injection & Over-Sharing |
| [SKILL003](SKILL003.md) | Skill uses a capability it does not declare | high | MCP02:2025 – Privilege Escalation via Scope Creep |
| [SKILL004](SKILL004.md) | Skill downloads and executes remote code | high | MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering |
| [SKILL005](SKILL005.md) | Skill sends data to a hardcoded external endpoint | high | MCP01:2025 – Token Mismanagement & Secret Exposure |
| [SKILL006](SKILL006.md) | Skill ships a script that deletes files wholesale | high | MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering |

Each page carries the same sections: the risk, a vulnerable example, a clean
example, what the rule deliberately does **not** flag, and — for the rules
calibrated against a public attack corpus — the measurement that chose its
shape, including the candidates that were rejected for firing on real code.

## Diagnostics

Not detection rules. These report a problem with an **annotation** in the
scanned files rather than with the files' security, so they live in their own
`MCPSCAN###` namespace, are not in the rule registry, and cannot be selected
with `--rules` or turned off with `--disable`.

| ID | Name | Severity |
|---|---|---|
| [MCPSCAN001](MCPSCAN001.md) | Malformed suppression comment | info |

The top-level [README](../../README.md) has the quick-start, the CI usage and
the precision/recall summary.
