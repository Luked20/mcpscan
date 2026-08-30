import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';

/**
 * Parameter names that plausibly feed a shell or subprocess call.
 * Anchored (`^...$`) so e.g. `commandline_flags` doesn't match.
 */
const CMD_PARAM_NAME = /^(cmd|command|shell|script|exec|bash|sh|powershell|args|argv)$/i;

/** Schema keys that constrain a value to a known-safe set. No `format`: no string format constrains a shell command. */
const CONSTRAINT_KEYS = ['pattern', 'enum', 'const'] as const;

const EVIDENCE_MAX = 120;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function truncate(s: string): string {
  return s.length > EVIDENCE_MAX ? `${s.slice(0, EVIDENCE_MAX - 1)}…` : s;
}

/**
 * A property counts as constrained either directly (`pattern`/`enum`/`const`
 * on the property itself) or, for an array, through its `items` schema — an
 * `args: string[]` whose `items.pattern` restricts each element is not free-form,
 * even though the array property itself carries none of the three keys.
 */
function isConstrained(propRaw: Record<string, unknown>): boolean {
  if (CONSTRAINT_KEYS.some((k) => propRaw[k] !== undefined)) return true;
  const items = propRaw['items'];
  if (isPlainObject(items) && CONSTRAINT_KEYS.some((k) => items[k] !== undefined)) return true;
  return false;
}

export const MCP005 = {
  id: 'MCP005',
  title: 'Unconstrained command parameter',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP05:2025 – Command Injection & Execution',
  appliesTo: 'tool',
  check(tool: ToolDefinition) {
    if (tool.inputSchema === undefined) return [];

    const schema = tool.inputSchema;
    if (!isPlainObject(schema)) return [];
    const properties = schema['properties'];
    if (!isPlainObject(properties)) return [];

    const findings: PartialFinding[] = [];
    for (const [name, propRaw] of Object.entries(properties)) {
      if (!CMD_PARAM_NAME.test(name)) continue;
      if (!isPlainObject(propRaw)) continue;
      const type = propRaw['type'];
      if (type !== 'string' && type !== 'array') continue;
      if (isConstrained(propRaw)) continue;

      findings.push({
        location: tool.loc(['inputSchema', 'properties', name]),
        message:
          `Tool "${tool.name}" has parameter "${name}" (${type}) with no constraint on its value. ` +
          `Nothing in the schema stops it from carrying shell metacharacters or an arbitrary command.`,
        remediation:
          'Replace with an `enum` of permitted commands, or split into typed fields (an `operation` ' +
          'enum plus `args` with `items.pattern`). Execute with `execFile`/`spawn` without a shell — ' +
          'then "; rm -rf /" is a literal argument, not a command.',
        evidence: truncate(JSON.stringify({ [name]: propRaw })),
      });
    }
    return findings;
  },
} satisfies Rule;
