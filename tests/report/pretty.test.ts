import { describe, it, expect } from 'vitest';
import { formatPretty } from '../../src/report/pretty.js';
import type { Finding } from '../../src/core/types.js';
import type { ScanStats } from '../../src/scan.js';

const STATS: ScanStats = { filesExamined: 40, filesWithTools: 3, tools: 12, skills: 1 };

const f: Finding = {
  ruleId: 'MCP002', title: 'Caractere Unicode invisível em definição de tool',
  severity: 'critical', confidence: 'high', owasp: 'MCP03:2025 – Tool Poisoning',
  location: { file: 'src/tools.json', line: 14, column: 32, endLine: 14, endColumn: 40, jsonPath: 'tools[1].description' },
  message: 'A tool "x" tem 1 caractere invisível.',
  remediation: 'Remova os caracteres invisíveis.',
  helpUri: 'https://x/MCP002.md', provenance: 'static',
};

describe('formatPretty', () => {
  const out = formatPretty([f], { color: false, stats: STATS });
  it('mostra severidade, regra e localização clicável', () => {
    expect(out).toContain('CRITICAL');
    expect(out).toContain('MCP002');
    expect(out).toContain('src/tools.json:14:32');
  });
  it('sempre mostra Fix e link', () => {
    expect(out).toContain('Fix:');
    expect(out).toContain('https://x/MCP002.md');
  });
  it('sem cor não emite códigos ANSI', () => {
    expect(out).not.toContain('[');
  });
  it('diz explicitamente quando não há nada', () => {
    expect(formatPretty([], { color: false, stats: STATS }))
      .toContain('Nenhum problema encontrado');
  });
  it('separa arquivos examinados de arquivos com tools no cabeçalho', () => {
    expect(out).toContain('40 arquivo(s) examinado(s)');
    expect(out).toContain('3 com tools');
    expect(out).toContain('12 tool(s)');
    expect(out).toContain('1 skill(s)');
  });
});

describe('formatPretty: scan que não olhou nada', () => {
  const zero: ScanStats = { filesExamined: 0, filesWithTools: 0, tools: 0, skills: 0 };
  const out = formatPretty([], {
    color: false, stats: zero, error: 'nenhum MCP server ou agent skill encontrado em src',
  });

  it('não se parece com um scan limpo', () => {
    expect(out).not.toContain('Nenhum problema encontrado');
  });
  it('diz que não conseguiu olhar e mostra o motivo', () => {
    expect(out).toContain('não consegui olhar');
    expect(out).toContain('nenhum MCP server ou agent skill encontrado em src');
  });
  it('mostra findings parciais junto do erro quando existem', () => {
    const partial = formatPretty([f], { color: false, stats: zero, error: 'regra(s) falharam' });
    expect(partial).toContain('MCP002');
    expect(partial).toContain('regra(s) falharam');
  });
});
