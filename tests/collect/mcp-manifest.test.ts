import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';

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
    const loc = collectManifest(FILE, text)[0]!.loc(['description']);
    expect(loc.line).toBe(5);
    expect(loc.file).toBe(FILE);
  });
  it('falls back to origin when the jsonPath does not exist', () => {
    const t = collectManifest(FILE, text)[0]!;
    expect(t.loc(['naoExiste'])).toEqual(t.origin);
  });
  it('ignores JSON without tools[]', () => {
    expect(collectManifest('x.json', '{"foo":1}')).toEqual([]);
  });
  it('does not blow up on invalid JSON', () => {
    expect(collectManifest('x.json', '{ nope')).toEqual([]);
  });
});

describe('collectManifest — serverName derivation', () => {
  it('uses the root-level "name" field when present', () => {
    const src = JSON.stringify({ name: 'my-server', tools: [{ name: 'a' }] });
    const [tool] = collectManifest('servers/whatever/tools.json', src);
    expect(tool!.serverName).toBe('my-server');
  });

  it('falls back to the containing directory when there is no root "name"', () => {
    const src = JSON.stringify({ tools: [{ name: 'a' }] });
    const [tool] = collectManifest('servers/server-a/tools.json', src);
    expect(tool!.serverName).toBe('servers/server-a');
  });

  it('falls back to the basename (extension stripped) when the file sits at the scan root', () => {
    const src = JSON.stringify({ tools: [{ name: 'a' }] });
    const [tool] = collectManifest('tools.json', src);
    expect(tool!.serverName).toBe('tools');
  });

  it('two tools from different files get different serverName values', () => {
    const srcA = JSON.stringify({ tools: [{ name: 'shared_tool' }] });
    const srcB = JSON.stringify({ tools: [{ name: 'shared_tool' }] });
    const [toolA] = collectManifest('server-a/tools.json', srcA);
    const [toolB] = collectManifest('server-b/tools.json', srcB);
    expect(toolA!.serverName).not.toBe(toolB!.serverName);
    expect(toolA!.serverName).toBe('server-a');
    expect(toolB!.serverName).toBe('server-b');
  });

  it('an empty string "name" does not win over the directory fallback', () => {
    const src = JSON.stringify({ name: '', tools: [{ name: 'a' }] });
    const [tool] = collectManifest('server-a/tools.json', src);
    expect(tool!.serverName).toBe('server-a');
  });
});

describe('loc addresses fields by segment, so a key may contain anything', () => {
  const t = () => collectManifest(FILE, text)[0]!;

  it('resolves a property whose name contains a dot', () => {
    // The regression this API exists for. While `loc()` took a joined string, a
    // path like `...properties.my.path` re-split into two segments, resolved to
    // nothing, and silently reported the whole tool instead of the property.
    const src = JSON.stringify({
      tools: [{ name: 'a', inputSchema: { properties: { 'my.path': { type: 'string' } } } }],
    });
    const tool = collectManifest('x.json', src)[0]!;
    const loc = tool.loc(['inputSchema', 'properties', 'my.path']);

    expect(loc).not.toEqual(tool.origin);
    expect(loc.jsonPath).toBe('tools[0].inputSchema.properties["my.path"]');
  });

  it('still falls back to origin for a path that does not exist', () => {
    const tool = t();
    expect(tool.loc(['inputSchema', 'properties', 'nope'])).toEqual(tool.origin);
  });

  it('an empty path addresses the subject itself', () => {
    const tool = t();
    const loc = tool.loc([]);
    expect(loc.line).toBe(tool.origin.line);
    expect(loc.column).toBe(tool.origin.column);
  });

  it('renders an ordinary path in dotted form', () => {
    const loc = collectManifest(FILE, text)[0]!.loc(['description']);
    expect(loc.jsonPath).toBe('tools[0].description');
  });
});
