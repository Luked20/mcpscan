import type { PartialFinding, Rule, ScanTarget, ToolDefinition } from '../../core/types.js';

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

/**
 * A sentence in which a tool description states that the server only reaches a
 * restricted set of directories — "Only works within allowed directories.",
 * "Both source and destination must be within allowed directories."
 *
 * Three parts, all required, all inside one sentence (`[^.?!]`): a restrictive
 * framing ("only works", "must be", "restricted"), a permission word
 * ("allowed", "permitted"), and a directory noun. Requiring all three is what
 * keeps this from matching ordinary prose that merely mentions a directory.
 */
const DECLARED_SCOPE_RE =
  /\b(?:only\s+(?:works?|operates?|reads?|writes?|accesses)|must\s+(?:be|stay|remain)|restricted|confined|limited|sandboxed|scoped)\b[^.?!]{0,80}?\b(?:allowed|permitted|approved|configured|whitelisted)\b[^.?!]{0,40}?\b(?:director(?:y|ies)|folder|folders|root|roots|path|paths)\b/i;

/**
 * Findings for one tool, before the manifest-level scope exemption below is
 * applied. Unconditional: every condition here is a property of the tool alone.
 */
function checkTool(tool: ToolDefinition): PartialFinding[] {
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
      location: tool.loc(['inputSchema', 'properties', name]),
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
}

/**
 * MCP004 — unconstrained path parameter in a file tool (docs/SPEC.md §7 catalog).
 *
 * `appliesTo: 'target'` rather than `'tool'` for one reason: the **scope
 * exemption** below is a property of the manifest, not of the individual tool,
 * so the rule has to see every tool in a file before it can judge any of them.
 *
 * ## The scope exemption
 *
 * A file-reading tool *must* take a path — that is what it is for. Applied
 * literally, this rule therefore fires on every correctly built file server,
 * which makes it a tax on the category rather than a signal. The regression
 * corpus (docs/SPEC.md §8.2) demonstrated exactly that: the official
 * `@modelcontextprotocol/server-filesystem` produced **nine** `high` findings,
 * while doing the one thing that actually works — validating every path in the
 * handler against an allow-list of roots supplied at startup.
 *
 * That server says so, in its own tool descriptions: "Only works within allowed
 * directories." So when any tool in a manifest makes that claim explicitly,
 * every path parameter in *that same manifest file* is exempt.
 *
 * **Why manifest-wide and not per tool.** The allow-list is a property of the
 * server process, not of one tool: the same handler enforces it for every tool
 * the server exposes. Per-tool checking would clear `read_text_file` and flag
 * `read_file` — the deprecated alias two entries above it, same parameter, same
 * server, whose one-line description has no room for the claim. A report that
 * contradicts itself inside a single file is a worse outcome than the finding
 * is worth. The unit is the manifest file, the same "one file is one
 * deployment" rule MCP006 uses.
 *
 * **What this gives up**, recorded as an accepted false negative in
 * docs/rules/MCP004.md: a manifest can state a restriction it does not enforce,
 * and one such sentence anywhere in the file exempts every tool in it. That is
 * the standing limitation of reading a manifest instead of running the server
 * (SPEC §14) — this rule reports what a server *declares*. The alternative,
 * measured against real servers, was nine false positives on the most widely
 * used MCP server there is.
 */
export const MCP004 = {
  id: 'MCP004',
  title: 'Unconstrained path parameter in a file tool',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP02:2025 – Privilege Escalation via Scope Creep',
  appliesTo: 'target',
  check(target: ScanTarget) {
    // One pass to find which manifests declare a restricted scope, then a
    // second to report -- a claim made by the last tool in a file still has to
    // exempt the first.
    const scopedFiles = new Set<string>();
    for (const tool of target.tools) {
      if (tool.description !== undefined && DECLARED_SCOPE_RE.test(tool.description)) {
        scopedFiles.add(tool.origin.file);
      }
    }

    return target.tools
      .filter((tool) => !scopedFiles.has(tool.origin.file))
      .flatMap(checkTool);
  },
} satisfies Rule;
