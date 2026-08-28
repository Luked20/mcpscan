import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';

const FILE = 'tests/fixtures/manifest/basic.json';
const text = readFileSync(FILE, 'utf8');

describe('collectManifest', () => {
  it('extrai a tool', () => {
    const tools = collectManifest(FILE, text);
    expect(tools).toHaveLength(1);
    expect(tools[0]!.name).toBe('read_file');
    expect(tools[0]!.description).toBe('Lê um arquivo do disco.');
  });
  it('aponta a linha exata da description', () => {
    const loc = collectManifest(FILE, text)[0]!.loc('tools[0].description');
    expect(loc.line).toBe(5);
    expect(loc.file).toBe(FILE);
  });
  it('cai no origin quando o jsonPath não existe', () => {
    const t = collectManifest(FILE, text)[0]!;
    expect(t.loc('tools[0].naoExiste')).toEqual(t.origin);
  });
  it('ignora JSON que não tem tools[]', () => {
    expect(collectManifest('x.json', '{"foo":1}')).toEqual([]);
  });
  it('não explode em JSON inválido', () => {
    expect(collectManifest('x.json', '{ nope')).toEqual([]);
  });
});
