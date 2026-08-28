import { describe, it, expect } from 'vitest';
import { formatPretty } from '../../src/report/pretty.js';
import type { Finding } from '../../src/core/types.js';

const f: Finding = {
  ruleId: 'MCP002', title: 'Caractere Unicode invisível em definição de tool',
  severity: 'critical', confidence: 'high', owasp: 'MCP03:2025 – Tool Poisoning',
  location: { file: 'src/tools.json', line: 14, column: 32, endLine: 14, endColumn: 40, jsonPath: 'tools[1].description' },
  message: 'A tool "x" tem 1 caractere invisível.',
  remediation: 'Remova os caracteres invisíveis.',
  helpUri: 'https://x/MCP002.md', provenance: 'static',
};

describe('formatPretty', () => {
  const out = formatPretty([f], { color: false, stats: { files: 3, tools: 12, skills: 1 } });
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
    expect(formatPretty([], { color: false, stats: { files: 3, tools: 12, skills: 1 } }))
      .toContain('Nenhum problema encontrado');
  });
});
