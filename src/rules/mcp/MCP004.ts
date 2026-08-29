import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';

/**
 * Parameter names that plausibly carry a filesystem path.
 * Anchored (`^...$`) so e.g. `pathological_input` or `filepath_hint` don't match.
 */
const PATH_PARAM_NAME = /^(path|file|filename|filepath|dir|directory|target|source|dest|destination)$/i;

/** Schema keys that constrain a string to a known-safe shape. */
const CONSTRAINT_KEYS = ['pattern', 'enum', 'const', 'format'] as const;

/**
 * File verbs and nouns (with common inflections), used to decide whether the
 * tool itself is a file tool — condition 3 of this rule. Spelled out as
 * explicit word lists rather than a stemming regex: a param like "path" is
 * common outside file tools (URL builders, routing, k8s), so the third
 * condition is load-bearing and needs to be exact, not approximate.
 */
const FILE_VERB_WORDS = new Set([
  'read', 'reads', 'reading',
  'write', 'writes', 'writing',
  'open', 'opens', 'opening', 'opened',
  'load', 'loads', 'loading', 'loaded',
  'save', 'saves', 'saving', 'saved',
  'delete', 'deletes', 'deleting', 'deleted',
  'remove', 'removes', 'removing', 'removed',
  'list', 'lists', 'listing', 'listed',
  'append', 'appends', 'appending', 'appended',
  'copy', 'copies', 'copying', 'copied',
  'move', 'moves', 'moving', 'moved',
]);

const FILE_NOUN_WORDS = new Set([
  'file', 'files', 'disk', 'filesystem', 'directory', 'directories', 'folder', 'folders', 'path', 'paths',
]);

/** A verb and a noun must land within this many tokens of each other to count as a match. */
const PROXIMITY_WINDOW = 4;

const EVIDENCE_MAX = 120;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function truncate(s: string): string {
  return s.length > EVIDENCE_MAX ? `${s.slice(0, EVIDENCE_MAX - 1)}…` : s;
}

/**
 * True when the tool's own name/description reads as a file operation: a
 * file verb (read, write, list, ...) within a few tokens of a file noun
 * (file, path, directory, ...). Proximity, not mere co-occurrence, is what
 * distinguishes "Reads a file from disk" from "Returns the number of open
 * network connections. See also the file-based variant." — the latter has
 * both an FILE_VERB_WORDS token ("open") and a FILE_NOUN_WORDS token
 * ("file"), six tokens apart, describing two unrelated things.
 */
function isFileTool(tool: ToolDefinition): boolean {
  const text = `${tool.name.replace(/_/g, ' ')} ${tool.description ?? ''}`.toLowerCase();
  const words = text.match(/[a-z]+/g) ?? [];

  const verbIndexes: number[] = [];
  const nounIndexes: number[] = [];
  words.forEach((w, i) => {
    if (FILE_VERB_WORDS.has(w)) verbIndexes.push(i);
    if (FILE_NOUN_WORDS.has(w)) nounIndexes.push(i);
  });

  return verbIndexes.some((v) => nounIndexes.some((n) => Math.abs(v - n) <= PROXIMITY_WINDOW));
}

export const MCP004 = {
  id: 'MCP004',
  title: 'Unconstrained path parameter in a file tool',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP02:2025 – Privilege Escalation via Scope Creep',
  appliesTo: 'tool',
  check(tool: ToolDefinition) {
    if (tool.inputSchema === undefined) return [];
    if (!isFileTool(tool)) return [];

    const schema = tool.inputSchema;
    if (!isPlainObject(schema)) return [];
    const properties = schema['properties'];
    if (!isPlainObject(properties)) return [];

    const findings: PartialFinding[] = [];
    for (const [name, propRaw] of Object.entries(properties)) {
      if (!PATH_PARAM_NAME.test(name)) continue;
      if (!isPlainObject(propRaw)) continue;
      if (propRaw['type'] !== 'string') continue;
      if (CONSTRAINT_KEYS.some((k) => propRaw[k] !== undefined)) continue;

      findings.push({
        location: tool.loc(`${tool.origin.jsonPath}.inputSchema.properties.${name}`),
        message:
          `Tool "${tool.name}" has parameter "${name}" typed as an unconstrained string. Nothing ` +
          `in the schema stops it from carrying an absolute path or a "../" traversal outside the ` +
          `tool's intended directory.`,
        remediation:
          `Constrain "${name}" in the schema with a \`pattern\` anchored to an allowed directory, ` +
          `or an \`enum\`. Also validate in the handler by resolving the path and confirming it ` +
          `stays inside the permitted root — a schema \`pattern\` alone does not stop ".." ` +
          `traversal after resolution.`,
        evidence: truncate(JSON.stringify({ [name]: propRaw })),
      });
    }
    return findings;
  },
} satisfies Rule;
