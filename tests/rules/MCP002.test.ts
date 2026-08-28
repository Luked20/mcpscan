import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { MCP002 } from '../../src/rules/mcp/MCP002.js';

const ctx = { target: { root: '.', servers: [], tools: [], skills: [], sourceFiles: [] }, helpBaseUri: 'https://x/' };
const load = (kind: 'vulnerable' | 'clean') => {
  const f = `tests/fixtures/MCP002/${kind}/tools.json`;
  return collectManifest(f, readFileSync(f, 'utf8'));
};

describe('MCP002 hidden-unicode-in-tool', () => {
  it('detecta tag characters na description', () => {
    const findings = load('vulnerable').flatMap((t) => MCP002.check(t, ctx as never));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].description');
    expect(findings[0]!.message).toContain('U+E0049');
  });
  it('não dispara em descrição limpa', () => {
    expect(load('clean').flatMap((t) => MCP002.check(t, ctx as never))).toEqual([]);
  });
  it('não dispara em acentos e emoji legítimos', () => {
    const tools = collectManifest('x.json', JSON.stringify({
      tools: [{ name: 'a', description: 'Ação — coração ✅ ünïcode' }],
    }));
    expect(tools.flatMap((t) => MCP002.check(t, ctx as never))).toEqual([]);
  });
});
