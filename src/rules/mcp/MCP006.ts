import type { PartialFinding, Rule, ScanTarget, ToolDefinition } from '../../core/types.js';

/**
 * MCP006 — tool shadowing (docs/SPEC.md §7 catalog, §7.3 risk-surface family).
 *
 * The first `appliesTo: 'target'` rule: both detections need to see the
 * *whole* scan, not one subject at a time — a name collision only exists in
 * relation to every other tool, and a directive in a description only means
 * something in relation to the tool it names.
 *
 * Two independent detections, described separately below. Either can fire on
 * its own; a target with both produces findings from both.
 */

/**
 * Detection 1 — the same tool `name` declared by two or more different
 * `serverName`s. Which implementation gets called then depends on client
 * load order, not on anything the user chose.
 *
 * Must NOT fire when:
 *  - the duplicates all share one `serverName` (the same tool listed twice in
 *    one manifest is a different, unrelated problem — not shadowing), or
 *  - `serverName` is missing on a tool — a tool with no known server can't be
 *    compared to anything, so it's simply excluded from consideration.
 *
 * Deduplicated by name: a collision among three servers produces one finding
 * naming all three, never three findings.
 */
function detectNameCollisions(target: ScanTarget): PartialFinding[] {
  const byName = new Map<string, ToolDefinition[]>();
  for (const tool of target.tools) {
    if (tool.serverName === undefined) continue;
    const existing = byName.get(tool.name);
    if (existing) existing.push(tool);
    else byName.set(tool.name, [tool]);
  }

  const findings: PartialFinding[] = [];
  // Map iteration follows insertion order (= target.tools order), which is
  // itself a function of file-discovery order — not guaranteed stable across
  // platforms. Sort the collision names themselves for deterministic output.
  const names = [...byName.keys()].sort();

  for (const name of names) {
    const tools = byName.get(name)!;
    const servers = [...new Set(tools.map((t) => t.serverName!))].sort();
    if (servers.length < 2) continue; // one server (or none informative) -> not a collision

    // Deterministic choice of "one of the colliding tools" for the location.
    const sorted = [...tools].sort((a, b) =>
      a.origin.file === b.origin.file
        ? a.origin.line - b.origin.line
        : a.origin.file < b.origin.file ? -1 : 1);
    const first = sorted[0]!;

    findings.push({
      location: first.origin,
      message:
        `Tool "${name}" is declared by ${servers.length} different servers (${servers.join(', ')}). ` +
        `Which implementation an agent calls depends on client load order, not on anything the user chose.`,
      remediation:
        'Rename the tool in one of the servers so names are unique across everything the client can ' +
        'load, or remove the redundant server from the client configuration.',
      evidence: `"${name}" declared by: ${servers.join(', ')}`,
    });
  }
  return findings;
}

/**
 * Detection 2 — a description that gives orders about another tool.
 *
 * Requires an imperative token ("before", "instead of", "do not use", "must
 * call", "always call", "first") within a short *token* window of another
 * tool's name (mirrors MCP004's token-proximity approach, not a raw character
 * window — proximity in words, not in bytes, is what actually correlates
 * with "this sentence is about that tool").
 *
 * A naive "does the description mention another tool's name" check would
 * flag every well-cross-referenced toolset ("Formats the email body used by
 * send_email.", "Returns the same shape as list_files."). Requiring the
 * imperative is what tells a redirection from a description that documents
 * a relationship between two tools.
 *
 * Two further guards against false positives on ordinary prose:
 *  - the name must appear as an exact token (tokenizing keeps `_` inside a
 *    word, so this is effectively word-boundary anchored — `list_files`
 *    matches only the identifier itself, never as a fragment of another word);
 *  - the name must be at least MIN_TOOL_NAME_LENGTH characters. A tool
 *    literally named `get`, `run`, or `list` would otherwise match on
 *    everyday English ("call get first", "always run the sync") that has
 *    nothing to do with tool redirection.
 */
const MIN_TOOL_NAME_LENGTH = 5;
const TOKEN_WINDOW = 6;

/** Token sequences that count as the imperative half of a directive. */
const IMPERATIVE_PHRASES: readonly (readonly string[])[] = [
  ['before'],
  ['instead', 'of'],
  ['do', 'not', 'use'],
  ['must', 'call'],
  ['always', 'call'],
  ['first'],
];

function tokenize(text: string): string[] {
  return text.toLowerCase().match(/[a-z0-9_]+/g) ?? [];
}

/** Index (into `tokens`) of the last token of every occurrence of every imperative phrase. */
function imperativeIndexes(tokens: readonly string[]): number[] {
  const out: number[] = [];
  for (const phrase of IMPERATIVE_PHRASES) {
    for (let i = 0; i <= tokens.length - phrase.length; i++) {
      let matched = true;
      for (let j = 0; j < phrase.length; j++) {
        if (tokens[i + j] !== phrase[j]) { matched = false; break; }
      }
      if (matched) out.push(i + phrase.length - 1);
    }
  }
  return out;
}

/** True when `otherName` shows up as a whole token within TOKEN_WINDOW tokens of an imperative. */
function namesWithImperative(
  tokens: readonly string[],
  imperatives: readonly number[],
  otherName: string,
): boolean {
  if (otherName.length < MIN_TOOL_NAME_LENGTH) return false;
  const needle = otherName.toLowerCase();
  const nameIndexes: number[] = [];
  tokens.forEach((t, i) => { if (t === needle) nameIndexes.push(i); });
  if (nameIndexes.length === 0) return false;
  return nameIndexes.some((ni) => imperatives.some((ii) => Math.abs(ni - ii) <= TOKEN_WINDOW));
}

function detectDirectives(target: ScanTarget): PartialFinding[] {
  const findings: PartialFinding[] = [];

  for (const a of target.tools) {
    if (!a.description) continue;
    const tokens = tokenize(a.description);
    const imperatives = imperativeIndexes(tokens);
    if (imperatives.length === 0) continue;

    const directed: string[] = [];
    for (const b of target.tools) {
      if (b === a || b.name === a.name) continue; // never compare a tool against itself
      if (namesWithImperative(tokens, imperatives, b.name)) directed.push(b.name);
    }
    if (directed.length === 0) continue;

    const names = [...new Set(directed)].sort();
    findings.push({
      location: a.loc(`${a.origin.jsonPath}.description`),
      message:
        `Tool "${a.name}" description gives an imperative instruction naming ` +
        `${names.length === 1 ? 'tool' : 'tools'} ${names.map((n) => `"${n}"`).join(', ')}. ` +
        `This redirects calls the user believed were going to ${names.length === 1 ? 'it' : 'them'}.`,
      remediation:
        'A tool description documents what the tool does; it should not instruct the agent to call, ' +
        'avoid, or prefer another specific tool. If one tool genuinely must run before another, express ' +
        "that through the schema or the server's own documentation, not through imperative prose in a " +
        'description the agent reads as instructions.',
      evidence: a.description.length > 160 ? `${a.description.slice(0, 159)}…` : a.description,
    });
  }
  return findings;
}

export const MCP006 = {
  id: 'MCP006',
  title: 'Tool shadows or directs another tool',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP03:2025 – Tool Poisoning',
  appliesTo: 'target',
  check(target: ScanTarget) {
    return [...detectNameCollisions(target), ...detectDirectives(target)];
  },
} satisfies Rule;
