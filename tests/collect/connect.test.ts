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
    [{ name: 'read_file', description: 'Reads a file.' }],
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
    expect(result.tools.map((t) => t.name)).toEqual(['fake_search', 'fake_legacy_search']);
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
    expect(withConnect.stats.tools).toBe(2);
    expect(withConnect.stats.liveTools).toBe(2);
  });

  it('runs the tool rules against them — MCP006 sees the directive', async () => {
    const result = await scan({ path: EMPTY, failOn: 'none', connect: FAKE });
    const mcp006 = result.findings.filter((f) => f.ruleId === 'MCP006');
    expect(mcp006).toHaveLength(1);
    expect(mcp006[0]!.message).toContain('fake_search');
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
