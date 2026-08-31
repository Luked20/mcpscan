import type { PartialFinding, Rule, ScanTarget, ServerDefinition, ToolDefinition } from '../../core/types.js';

/**
 * MCP006 — tool shadowing (docs/SPEC.md §7 catalog, §7.3 risk-surface family).
 *
 * The first `appliesTo: 'target'` rule: every detection needs to see the
 * *whole* scan, not one subject at a time — a name collision only exists in
 * relation to every other tool, and a directive in a description only means
 * something in relation to the tool it names.
 *
 * Three independent detections, described separately below (1, 1b, 2). Any
 * can fire on its own; a target that trips more than one produces findings
 * from each.
 *
 * ## Static and live tools are never compared against each other
 *
 * Both tool detections run twice — once over tools read from files, once over
 * tools captured with `--connect` — and never across the two. `--connect`
 * created this problem the moment it existed: scanning a server's own
 * repository *and* starting that server finds the same tools twice, by two
 * routes.
 *
 * `czlonkowski/n8n-mcp` is the worked example. Its repository ships a
 * `manifest.json` declaring `"name": "n8n-mcp"` with 23 tools; the running
 * server introduces itself as `n8n-documentation-mcp` and reports 7. Seven
 * names overlap, the two documents are different files with different declared
 * names, and detection 1 duly reported seven collisions between "two servers"
 * that are one piece of software seen twice.
 *
 * A client cannot load a repository. Comparing a live capture against a
 * manifest found in the same scan answers a question nobody asked.
 */

/**
 * Detection 1 — the same tool `name` declared by two or more different
 * servers. Which implementation gets called then depends on client load
 * order, not on anything the user chose.
 *
 * Requires evidence that the colliding servers are actually co-loaded — a
 * name collision between tools nobody ever loads together is not a finding,
 * it's a coincidence. The evidence this scanner can see: the manifest
 * *explicitly declares* its own server name (a root-level `"name"` field).
 * That is a claim the author made. A name this scanner *derived* from the
 * containing directory (`tools.json` living in `server-a/`) is a guess this
 * scanner made, not evidence of anything — two unrelated fixture directories
 * that both happen to expose `read_file` prove nothing about what any real
 * client loads. See `ToolDefinition.serverNameSource` in `core/types.ts`.
 *
 * "Different servers" is measured by *manifest file*, not by the declared
 * name string. Two tool entries from the very same file are one manifest
 * listing a tool twice — a duplicate-listing problem, not shadowing, and
 * excluded regardless of what its `name` field says. Two entries from two
 * *different* files are two separate deployments even when both files
 * explicitly declared the identical name — and picking the same identity is
 * itself part of what makes that collision worth flagging: an agent has no
 * way to tell the two apart either.
 *
 * Must NOT fire when:
 *  - `serverName` is missing on a tool — a tool with no known server can't be
 *    compared to anything, so it's simply excluded from consideration,
 *  - `serverNameSource` is `'derived'` on a tool — see above. A derived name
 *    is excluded even when it happens to collide with a *declared* name on
 *    the other side: this scanner cannot tell whether the directory-derived
 *    "server" is the same deployment as the one that declared its name, so
 *    treating that pairing as a collision would be exactly the kind of guess
 *    this restriction exists to rule out, or
 *  - every declared occurrence of the name comes from one manifest file.
 *
 * Deduplicated by file: a collision among three servers produces one finding
 * naming all three, never three findings.
 */
function detectNameCollisions(tools: readonly ToolDefinition[]): PartialFinding[] {
  const byName = new Map<string, ToolDefinition[]>();
  for (const tool of tools) {
    if (tool.serverNameSource !== 'declared') continue;
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

    // One entry per distinct manifest file (first tool wins as that file's
    // representative — only its serverName and location end up in the finding).
    const byFile = new Map<string, ToolDefinition>();
    for (const tool of tools) {
      if (!byFile.has(tool.origin.file)) byFile.set(tool.origin.file, tool);
    }
    if (byFile.size < 2) continue; // one manifest file -> not a collision

    const entries = [...byFile.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
    const labels = entries.map(([, tool]) => tool.serverName!);
    const first = entries[0]![1];

    findings.push({
      location: first.origin,
      message:
        `Tool "${name}" is declared by ${entries.length} different servers (${labels.join(', ')}). ` +
        `Which implementation an agent calls depends on client load order, not on anything the user chose.`,
      remediation:
        'Rename the tool in one of the servers so names are unique across everything the client can ' +
        'load, or remove the redundant server from the client configuration.',
      evidence: `"${name}" declared by: ${labels.join(', ')}`,
    });
  }
  return findings;
}

/**
 * Detection 1b — two *server entries in the same MCP client config file*
 * (`.mcp.json` / `mcp.json` / `claude_desktop_config.json`) that launch the
 * identical command. Entries in one such file really are loaded together by
 * that client — the strongest co-loading evidence available — so two names
 * that both resolve to the same `command` + `args` are the same server code
 * running twice under different names, which is a real collision worth
 * flagging even though `ServerDefinition.tools` is always empty (this
 * scanner never executes a server to ask it for its tool list).
 *
 * Scoped to `stdio` servers with a `command`: `http`/`sse` servers are
 * compared by `url` instead, since `command` is absent for those. A server
 * with neither (`transport: 'unknown'`) has nothing reliable to key on and
 * is excluded rather than guessed at.
 *
 * Grouped by `origin.file` first — two servers with the same command in two
 * *different* config files is not evidence of anything; nothing says both
 * files are ever loaded by the same client.
 */
function serverIdentity(server: ServerDefinition): string | undefined {
  if (server.transport === 'stdio' && server.command !== undefined) {
    return `stdio:${server.command} ${(server.args ?? []).join(' ')}`;
  }
  if ((server.transport === 'http' || server.transport === 'sse') && server.url !== undefined) {
    return `${server.transport}:${server.url}`;
  }
  return undefined;
}

function detectConfigServerCollisions(target: ScanTarget): PartialFinding[] {
  const byFile = new Map<string, ServerDefinition[]>();
  for (const server of target.servers) {
    const existing = byFile.get(server.origin.file);
    if (existing) existing.push(server);
    else byFile.set(server.origin.file, [server]);
  }

  const findings: PartialFinding[] = [];
  for (const file of [...byFile.keys()].sort()) {
    const byIdentity = new Map<string, ServerDefinition[]>();
    for (const server of byFile.get(file)!) {
      const identity = serverIdentity(server);
      if (identity === undefined) continue;
      const existing = byIdentity.get(identity);
      if (existing) existing.push(server);
      else byIdentity.set(identity, [server]);
    }

    for (const identity of [...byIdentity.keys()].sort()) {
      const servers = byIdentity.get(identity)!;
      const names = [...new Set(servers.map((s) => s.name))].sort();
      if (names.length < 2) continue; // one name (config re-declared it once) -> not a collision

      const sorted = [...servers].sort((a, b) => a.origin.line - b.origin.line);
      const first = sorted[0]!;
      const command = identity.slice(identity.indexOf(':') + 1);

      findings.push({
        location: first.origin,
        message:
          `${file} declares ${names.length} servers (${names.join(', ')}) that all run "${command}". ` +
          `A client loading this config runs the same server code under multiple names — any tool name ` +
          `collision between them is real, not incidental.`,
        remediation:
          'Remove the redundant entry, or confirm the two names are intentionally separate deployments ' +
          'of the same package (e.g. pointed at different data) rather than an accidental duplicate.',
        evidence: `${names.join(', ')} -> "${command}"`,
      });
    }
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

/**
 * The named tool must come from a **different manifest**.
 *
 * A description that says "call `get_board_info` first" about another tool of
 * the *same* server is that server documenting its own workflow. The author
 * already owns both ends: if they wanted to redirect a call, they would change
 * the tool, not write prose about it. Prose redirection is an attack
 * specifically when it points somewhere its author does not control — another
 * server's tool, which the agent will happily prefer because a description told
 * it to.
 *
 * This condition was added after `--connect` made real tool sets reachable, and
 * it was not a close call. Two servers, measured:
 *
 *   `@mondaydotcomorg/monday-api-mcp`   88 tools -> **38** findings
 *   `firecrawl-mcp-server`              27 tools ->    1 finding
 *
 * Every one of the 39 was intra-server, and reading them they are plainly house
 * style: `get_form` and `update_form` referring to each other,
 * `list_automations` pointing at `manage_automations`, a deprecated entry point
 * naming its replacement. A rule that fires 38 times on one well-documented
 * server is a tax on documenting tools well, not a signal — the same shape as
 * SKILL003's five-out-of-five and MCP008's four-out-of-five.
 *
 * What it gives up is recorded in docs/rules/MCP006.md: a genuinely malicious
 * server can hide a directive among its own tools, and a single-server scan
 * has nothing to compare against at all.
 */
function detectDirectives(tools: readonly ToolDefinition[]): PartialFinding[] {
  const findings: PartialFinding[] = [];

  for (const a of tools) {
    if (!a.description) continue;
    const tokens = tokenize(a.description);
    const imperatives = imperativeIndexes(tokens);
    if (imperatives.length === 0) continue;

    const directed: string[] = [];
    for (const b of tools) {
      if (b === a || b.name === a.name) continue; // never compare a tool against itself
      // Only a tool in a *different* manifest counts. See the note below.
      if (b.origin.file === a.origin.file) continue;
      if (namesWithImperative(tokens, imperatives, b.name)) directed.push(b.name);
    }
    if (directed.length === 0) continue;

    const names = [...new Set(directed)].sort();
    findings.push({
      location: a.loc(['description']),
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
    // Static and live tools are compared only against their own kind -- see the
    // provenance note in this file's header.
    const staticTools = target.tools.filter((t) => t.provenance !== 'live');
    const liveTools = target.tools.filter((t) => t.provenance === 'live');

    return [
      ...detectNameCollisions(staticTools),
      ...detectNameCollisions(liveTools),
      ...detectConfigServerCollisions(target),
      ...detectDirectives(staticTools),
      ...detectDirectives(liveTools),
    ];
  },
} satisfies Rule;
