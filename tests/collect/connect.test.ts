import { describe, it, expect } from 'vitest';
import { connectAndListTools, readMessages, toolsFromListResult } from '../../src/collect/connect.js';
import { scan } from '../../src/scan.js';

/**
 * The servers here are real stdio MCP servers, small enough to live in
 * `tests/fixtures/connect/`. Nothing is downloaded and no third-party package
 * runs — but the handshake, the framing and the failure paths are the real
 * ones, which a mock of `spawn` would not have exercised.
 */
const FAKE = 'node tests/fixtures/connect/server.mjs';
const REJECTS = 'node tests/fixtures/connect/rejects.mjs';
const CRASHES = 'node tests/fixtures/connect/crashes.mjs';
const SILENT = 'node tests/fixtures/connect/silent.mjs';

describe('readMessages', () => {
  it('reads several messages out of one chunk', () => {
    const { messages, rest } = readMessages('{"id":1}\n{"id":2}\n');
    expect(messages.map((m) => m.id)).toEqual([1, 2]);
    expect(rest).toBe('');
  });

  it('keeps a partial line for the next chunk', () => {
    const first = readMessages('{"id":1}\n{"id":');
    expect(first.messages.map((m) => m.id)).toEqual([1]);
    expect(readMessages(first.rest + '2}\n').messages.map((m) => m.id)).toEqual([2]);
  });

  it('skips a line that is not JSON rather than failing', () => {
    // Servers print banners and warnings to stdout; that is not an error.
    const { messages } = readMessages('Listening on stdio...\n{"id":1}\n');
    expect(messages.map((m) => m.id)).toEqual([1]);
  });
});

describe('toolsFromListResult', () => {
  const result = toolsFromListResult(
    { tools: [{ name: 'read_file', description: 'Reads a file.' }] },
    'fake-server',
  );

  it('produces tools with real positions inside the returned document', () => {
    expect(result.tools).toHaveLength(1);
    expect(result.tools[0]!.origin.line).toBeGreaterThan(1);
    expect(result.tools[0]!.loc(['description']).line).toBeGreaterThan(1);
  });

  it('names the document so it cannot collide with a real path', () => {
    // MCP006 treats one file as one deployment, so a live document sharing a
    // name with a scanned file would merge two unrelated servers.
    expect(result.file).toBe('connect:fake-server/tools.json');
  });

  it('carries the server\'s own reported name as a declared server identity', () => {
    expect(result.tools[0]!.serverName).toBe('fake-server');
    expect(result.tools[0]!.serverNameSource).toBe('declared');
  });
});

describe('connectAndListTools', () => {
  it('completes the handshake and returns the tools', async () => {
    const result = await connectAndListTools({ command: FAKE });
    if (typeof result === 'string') throw new Error(`expected tools, got: ${result}`);

    expect(result.serverName).toBe('fake-server');
    expect(result.tools.map((t) => t.name)).toEqual(['fake_search', 'fake_legacy_search', 'fake_read_file']);
  });

  it('reports a server that refuses tools/list', async () => {
    const result = await connectAndListTools({ command: REJECTS });
    expect(result).toBe('node tests/fixtures/connect/rejects.mjs rejected tools/list: tools are not available');
  });

  it('reports a server that dies, including its stderr', async () => {
    const result = await connectAndListTools({ command: CRASHES });
    expect(typeof result).toBe('string');
    expect(result as string).toContain('exited');
    expect(result as string).toContain('MISSING_API_KEY');
  });

  it('reports a command that does not exist', async () => {
    const result = await connectAndListTools({ command: 'definitely-not-a-real-binary-xyz' });
    expect(typeof result).toBe('string');
  });

  it('times out rather than hanging on a server that never answers', async () => {
    const result = await connectAndListTools({ command: SILENT, timeoutMs: 800 });
    expect(result).toContain('did not answer within');
  }, 10_000);

  it('rejects an empty command', async () => {
    expect(await connectAndListTools({ command: '   ' })).toContain('needs a command');
  });
});

describe('--connect end to end', () => {
  const EMPTY = 'tests/fixtures/empty';

  it('finds tools a directory scan cannot see', async () => {
    // The whole point: the directory holds no manifest, so without --connect
    // there is nothing for MCP001-MCP006 to run on.
    const withoutConnect = await scan({ path: EMPTY, failOn: 'none' });
    expect(withoutConnect.exitCode).toBe(2); // no subjects at all

    const withConnect = await scan({ path: EMPTY, failOn: 'none', connect: FAKE });
    expect(withConnect.error).toBeUndefined();
    expect(withConnect.stats.tools).toBe(3);
    expect(withConnect.stats.liveTools).toBe(3);
  });

  it('runs the tool rules against them — MCP004 sees the unconstrained path', async () => {
    const result = await scan({ path: EMPTY, failOn: 'none', connect: FAKE });
    const mcp004 = result.findings.filter((f) => f.ruleId === 'MCP004');
    expect(mcp004).toHaveLength(1);
    expect(mcp004[0]!.message).toContain('fake_read_file');
  });

  it('does NOT report a directive naming a tool of the same server', async () => {
    // fake_legacy_search points at fake_search, and both come from this one
    // server. Measured on monday and firecrawl, that shape is documentation:
    // see MCP006 detection 2.
    const result = await scan({ path: EMPTY, failOn: 'none', connect: FAKE });
    expect(result.findings.filter((f) => f.ruleId === 'MCP006')).toEqual([]);
  });

  it('labels those findings as live, not static', async () => {
    const result = await scan({ path: EMPTY, failOn: 'none', connect: FAKE });
    expect(result.findings.every((f) => f.provenance === 'live')).toBe(true);
  });

  it('is exit 2 when the server will not start — never a clean report', async () => {
    const result = await scan({ path: EMPTY, failOn: 'none', connect: CRASHES });
    expect(result.exitCode).toBe(2);
    expect(result.error).toContain('MISSING_API_KEY');
    expect(result.findings).toEqual([]);
  });

  it('leaves liveTools at zero when --connect is not used', async () => {
    const result = await scan({ path: 'tests/fixtures/MCP004/vulnerable', failOn: 'none' });
    expect(result.stats.liveTools).toBe(0);
    expect(result.findings.every((f) => f.provenance === 'static')).toBe(true);
  });
});

describe('--connect does not turn one server into two', () => {
  // czlonkowski/n8n-mcp ships a manifest.json declaring "n8n-mcp" with 23
  // tools; the running server introduces itself as "n8n-documentation-mcp"
  // and reports 7. Seven names overlap, so detection 1 reported seven
  // collisions between "two servers" that are one piece of software seen
  // twice, by two routes. A client cannot load a repository.
  const FAKE = 'node tests/fixtures/connect/server.mjs';
  const MANIFEST_DIR = 'tests/fixtures/connect/repo';

  it('does not report a collision between a live tool and a manifest of the same scan', async () => {
    const result = await scan({ path: MANIFEST_DIR, failOn: 'none', connect: FAKE });
    expect(result.findings.filter((f) => f.ruleId === 'MCP006')).toEqual([]);
  });

  it('still reports a collision between two manifests on disk', async () => {
    // The static side keeps working: this is the same directory, scanned
    // without --connect, against a second manifest that collides with it.
    const result = await scan({ path: 'tests/fixtures/MCP006/vulnerable', failOn: 'none' });
    expect(result.findings.filter((f) => f.ruleId === 'MCP006').length).toBeGreaterThan(0);
  });

  it('marks live tools so a rule can tell them apart', async () => {
    const result = await scan({ path: MANIFEST_DIR, failOn: 'none', connect: FAKE });
    expect(result.stats.liveTools).toBe(3);
    expect(result.stats.tools).toBeGreaterThan(3);
  });
});

describe('--connect collects all three MCP primitives', () => {
  // MCP has three: tools, resources and prompts. Until the recall corpus
  // measured it, this scanner collected the first only -- not a missing rule,
  // but two thirds of the protocol going unexamined. See docs/SPEC.md §8.5.
  const FULL = 'node tests/fixtures/connect/server.mjs';
  const TOOLS_ONLY = 'node tests/fixtures/connect/tools-only.mjs';

  it('reads resources, resource templates and prompts', async () => {
    const result = await connectAndListTools({ command: FULL });
    if (typeof result === 'string') throw new Error(`expected a capture, got: ${result}`);

    expect(result.resources.map((r) => r.uri)).toEqual(['config://settings', 'notes://{user_id}']);
    expect(result.prompts.map((p) => p.name)).toEqual(['summarise']);
  });

  it('tells a template apart from a plain resource', async () => {
    const result = await connectAndListTools({ command: FULL });
    if (typeof result === 'string') throw new Error(result);

    const [plain, template] = result.resources;
    expect(plain!.isTemplate).toBeUndefined();
    expect(template!.isTemplate).toBe(true);
    // The placeholder is the point: a template is a parameterised surface.
    expect(template!.uri).toContain('{user_id}');
  });

  it('keeps the fields a future rule will need', async () => {
    const result = await connectAndListTools({ command: FULL });
    if (typeof result === 'string') throw new Error(result);

    expect(result.resources[0]).toMatchObject({
      uri: 'config://settings', name: 'settings', mimeType: 'application/json', provenance: 'live',
    });
    expect(result.prompts[0]).toMatchObject({ name: 'summarise', provenance: 'live' });
    expect(result.prompts[0]!.arguments).toEqual([
      { name: 'document', description: 'The text to summarise.', required: true },
    ]);
  });

  it('gives them real positions inside the returned document', async () => {
    const result = await connectAndListTools({ command: FULL });
    if (typeof result === 'string') throw new Error(result);
    expect(result.resources[0]!.origin.line).toBeGreaterThan(1);
    expect(result.prompts[0]!.loc(['description']).line).toBeGreaterThan(1);
  });

  it('does not ask a tools-only server for what it never advertised', async () => {
    // That server answers -32601 to anything else. Asking anyway would turn
    // every ordinary server into a reported failure.
    const result = await connectAndListTools({ command: TOOLS_ONLY });
    if (typeof result === 'string') throw new Error(`expected a capture, got: ${result}`);

    expect(result.tools).toHaveLength(1);
    expect(result.resources).toEqual([]);
    expect(result.prompts).toEqual([]);
  });

  it('counts them in the scan stats', async () => {
    const result = await scan({ path: 'tests/fixtures/empty', failOn: 'none', connect: FULL });
    expect(result.stats.resources).toBe(2);
    expect(result.stats.prompts).toBe(1);
  });

  it('a server with only resources still counts as something to scan', async () => {
    // hasSubjects() decides exit 2. A server that exposes no tools but does
    // expose resources has plenty to look at, and must not read as "nothing here".
    const result = await scan({ path: 'tests/fixtures/empty', failOn: 'none', connect: FULL });
    expect(result.exitCode).not.toBe(2);
  });
});
