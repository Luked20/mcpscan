import { describe, it, expect } from 'vitest';
import { discover } from '../../src/collect/index.js';

describe('discover', () => {
  it('acha tools no diretório de fixtures', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable');
    expect(t.tools.map((x) => x.name)).toContain('read_file');
  });
  it('usa caminhos relativos com barra normal', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable');
    expect(t.tools[0]!.origin.file.includes('\\')).toBe(false);
  });
  it('não explode em diretório sem nada relevante', async () => {
    const t = await discover('tests/fixtures/empty');
    expect(t.tools).toEqual([]);
  });
  it('escaneia um arquivo passado diretamente', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable/tools.json');
    expect(t.tools.map((x) => x.name)).toContain('read_file');
  });
  it('usa o basename como caminho relativo do arquivo único', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable/tools.json');
    expect(t.tools[0]!.origin.file).toBe('tools.json');
  });
  it('conta os arquivos examinados, não só os que produziram tools', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable');
    expect(t.filesExamined).toBe(1);
  });
});
