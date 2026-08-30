import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectMcpConfig } from '../../src/collect/mcp-config.js';

const FILE = 'tests/fixtures/mcp-config/basic.mcp.json';
const text = readFileSync(FILE, 'utf8');

describe('collectMcpConfig', () => {
  it('extracts a stdio server', () => {
    const servers = collectMcpConfig(FILE, text);
    const files = servers.find((s) => s.name === 'files');
    expect(files).toBeDefined();
    expect(files!.transport).toBe('stdio');
    expect(files!.command).toBe('npx');
    expect(files!.args).toEqual(['-y', 'some-mcp@latest']);
    expect(files!.env).toEqual({ TOKEN: 'abc123' });
    expect(files!.tools).toEqual([]);
  });

  it('extracts an http server', () => {
    const servers = collectMcpConfig(FILE, text);
    const remote = servers.find((s) => s.name === 'remote');
    expect(remote).toBeDefined();
    expect(remote!.transport).toBe('http');
    expect(remote!.url).toBe('https://example.com/mcp');
    expect(remote!.command).toBeUndefined();
  });

  it('points origin.line at the real line of the server entry', () => {
    const servers = collectMcpConfig(FILE, text);
    const files = servers.find((s) => s.name === 'files')!;
    expect(files.origin.line).toBe(3);
    expect(files.origin.file).toBe(FILE);

    const remote = servers.find((s) => s.name === 'remote')!;
    expect(remote.origin.line).toBe(8);
  });

  it('resolves loc() for a nested env value precisely', () => {
    const files = collectMcpConfig(FILE, text).find((s) => s.name === 'files')!;
    const loc = files.loc(['env', 'TOKEN']);
    expect(loc.line).toBe(6);
    expect(loc.file).toBe(FILE);
  });

  it('falls back to origin when the jsonPath does not exist', () => {
    const files = collectMcpConfig(FILE, text).find((s) => s.name === 'files')!;
    expect(files.loc(['naoExiste'])).toEqual(files.origin);
  });

  it('returns [] when neither mcpServers nor servers is present', () => {
    expect(collectMcpConfig('x.json', '{"a":1}')).toEqual([]);
  });

  it('resolves a field of a server whose NAME contains a dot', () => {
    // Found in the wild, in awslabs/mcp: PyPI-style server names like
    // `awslabs.mysql-mcp-server` are ordinary. While loc() took a joined
    // string, `mcpServers.awslabs.mysql-mcp-server.args` re-split into four
    // segments, resolved to nothing, and the MCP007 finding silently pointed
    // at the whole server object instead of its args.
    const src = JSON.stringify({
      mcpServers: { 'awslabs.mysql-mcp-server': { command: 'uvx', args: ['awslabs.mysql-mcp-server@latest'] } },
    });
    const server = collectMcpConfig('x.json', src)[0]!;
    const loc = server.loc(['args']);

    expect(server.name).toBe('awslabs.mysql-mcp-server');
    expect(loc).not.toEqual(server.origin);
    expect(loc.jsonPath).toBe('mcpServers["awslabs.mysql-mcp-server"].args');
  });

  it('returns [] on malformed JSON', () => {
    expect(collectMcpConfig('x.json', '{ nope')).toEqual([]);
  });

  it('skips a server entry that is not an object rather than throwing', () => {
    const text2 = JSON.stringify({ mcpServers: { broken: 'not-an-object', ok: { command: 'node' } } });
    const servers = collectMcpConfig('x.json', text2);
    expect(servers).toHaveLength(1);
    expect(servers[0]!.name).toBe('ok');
  });

  it('also accepts the "servers" root key', () => {
    const file = 'tests/fixtures/mcp-config/servers-key.json';
    const servers = collectMcpConfig(file, readFileSync(file, 'utf8'));
    expect(servers).toHaveLength(1);
    expect(servers[0]!.name).toBe('local');
    expect(servers[0]!.transport).toBe('stdio');
  });

  it('classifies an sse url distinctly from a plain http url', () => {
    const text2 = JSON.stringify({ mcpServers: { s: { url: 'https://example.com/sse' } } });
    const servers = collectMcpConfig('x.json', text2);
    expect(servers[0]!.transport).toBe('sse');
  });

  it('classifies a server with neither command nor url as unknown', () => {
    const text2 = JSON.stringify({ mcpServers: { s: { note: 'nothing useful' } } });
    const servers = collectMcpConfig('x.json', text2);
    expect(servers[0]!.transport).toBe('unknown');
  });
});
