import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest, parseJsonPath } from '../../src/collect/mcp-manifest.js';

const FILE = 'tests/fixtures/manifest/basic.json';
const text = readFileSync(FILE, 'utf8');

describe('collectManifest', () => {
  it('extracts the tool', () => {
    const tools = collectManifest(FILE, text);
    expect(tools).toHaveLength(1);
    expect(tools[0]!.name).toBe('read_file');
    expect(tools[0]!.description).toBe('Lê um arquivo do disco.');
  });
  it('points at the exact line of the description', () => {
    const loc = collectManifest(FILE, text)[0]!.loc('tools[0].description');
    expect(loc.line).toBe(5);
    expect(loc.file).toBe(FILE);
  });
  it('falls back to origin when the jsonPath does not exist', () => {
    const t = collectManifest(FILE, text)[0]!;
    expect(t.loc('tools[0].naoExiste')).toEqual(t.origin);
  });
  it('ignores JSON without tools[]', () => {
    expect(collectManifest('x.json', '{"foo":1}')).toEqual([]);
  });
  it('does not blow up on invalid JSON', () => {
    expect(collectManifest('x.json', '{ nope')).toEqual([]);
  });
});

describe('parseJsonPath fails closed', () => {
  it('parses a well-formed path', () => {
    expect(parseJsonPath('tools[0].inputSchema.properties.path'))
      .toEqual(['tools', 0, 'inputSchema', 'properties', 'path']);
  });
  it('returns null on an empty path', () => {
    expect(parseJsonPath('')).toBeNull();
  });
  it('returns null on a malformed path', () => {
    expect(parseJsonPath('tools[0].name[')).toBeNull();
    expect(parseJsonPath('tools[0]..name')).toBeNull();
    expect(parseJsonPath('tools[x].name')).toBeNull();
  });
});

describe('loc falls back to origin instead of lying about the location', () => {
  const t = () => collectManifest(FILE, text)[0]!;

  it('a malformed path does not become the location of the whole object', () => {
    const tool = t();
    // Before: parseJsonPath returned ['tools', 0] and loc() stamped the location
    // of the entire tools[0] with the wrong jsonPath — plausible and authoritative-looking in SARIF.
    expect(tool.loc('tools[0].name[')).toEqual(tool.origin);
  });

  it('an empty path does not become the whole document', () => {
    const tool = t();
    // Before: [] -> findNodeAtLocation returned the root.
    expect(tool.loc('')).toEqual(tool.origin);
  });

  it('a key containing a dot degrades to origin, never to a wrong location', () => {
    const src = JSON.stringify({
      tools: [{ name: 'a', inputSchema: { properties: { 'my.path': { type: 'string' } } } }],
    });
    const tool = collectManifest('x.json', src)[0]!;
    const loc = tool.loc('tools[0].inputSchema.properties.my.path');
    expect(loc).toEqual(tool.origin);
  });
});
