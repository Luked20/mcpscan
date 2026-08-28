import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest, parseJsonPath } from '../../src/collect/mcp-manifest.js';

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

describe('parseJsonPath falha fechado', () => {
  it('parseia um caminho bem formado', () => {
    expect(parseJsonPath('tools[0].inputSchema.properties.path'))
      .toEqual(['tools', 0, 'inputSchema', 'properties', 'path']);
  });
  it('devolve null em caminho vazio', () => {
    expect(parseJsonPath('')).toBeNull();
  });
  it('devolve null em caminho malformado', () => {
    expect(parseJsonPath('tools[0].name[')).toBeNull();
    expect(parseJsonPath('tools[0]..name')).toBeNull();
    expect(parseJsonPath('tools[x].name')).toBeNull();
  });
});

describe('loc cai no origin em vez de mentir a localização', () => {
  const t = () => collectManifest(FILE, text)[0]!;

  it('caminho malformado não vira a localização do objeto inteiro', () => {
    const tool = t();
    // Antes: parseJsonPath devolvia ['tools', 0] e loc() carimbava a localização
    // do tools[0] inteiro com o jsonPath errado — plausível e autoritativo no SARIF.
    expect(tool.loc('tools[0].name[')).toEqual(tool.origin);
  });

  it('caminho vazio não vira o documento inteiro', () => {
    const tool = t();
    // Antes: [] -> findNodeAtLocation devolvia a raiz.
    expect(tool.loc('')).toEqual(tool.origin);
  });

  it('chave com ponto degrada para origin, nunca para uma localização errada', () => {
    const src = JSON.stringify({
      tools: [{ name: 'a', inputSchema: { properties: { 'my.path': { type: 'string' } } } }],
    });
    const tool = collectManifest('x.json', src)[0]!;
    const loc = tool.loc('tools[0].inputSchema.properties.my.path');
    expect(loc).toEqual(tool.origin);
  });
});
