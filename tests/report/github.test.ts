import { describe, it, expect } from 'vitest';
import { formatGithub } from '../../src/report/github.js';
import type { Finding, Severity } from '../../src/core/types.js';

const f: Finding = {
  ruleId: 'MCP002', title: 'Unicode invisível', severity: 'critical', confidence: 'high',
  location: { file: 'src/t.json', line: 14, column: 32, endLine: 14, endColumn: 40 },
  message: 'msg com\nquebra', remediation: 'fix', helpUri: 'https://x', provenance: 'static',
};

describe('formatGithub', () => {
  it('emite workflow command com file/line/col', () => {
    expect(formatGithub([f])).toContain('::error file=src/t.json,line=14,col=32');
  });
  it('escapa quebras de linha na mensagem', () => {
    expect(formatGithub([f])).toContain('%0A');
    expect(formatGithub([f]).split('\n')).toHaveLength(1);
  });
  it('mapeia severidade para comando correto (todas as cinco)', () => {
    const sevs: [Severity, string][] = [
      ['critical', 'error'], ['high', 'error'], ['medium', 'warning'],
      ['low', 'notice'], ['info', 'notice'],
    ];
    for (const [severity, cmd] of sevs) {
      const finding: Finding = { ...f, severity };
      expect(formatGithub([finding])).toContain(`::${cmd} file=`);
    }
  });
  it('escapa % literal como %25', () => {
    const finding: Finding = { ...f, message: '100% seguro', location: { ...f.location } };
    expect(formatGithub([finding])).toContain('100%25');
  });
  it('escapa carriage return como %0D', () => {
    const finding: Finding = { ...f, message: 'linha\rquebrada' };
    expect(formatGithub([finding])).toContain('%0D');
  });
  it('lista vazia produz string vazia', () => {
    expect(formatGithub([])).toBe('');
  });
  it('múltiplos findings produzem uma linha cada', () => {
    const out = formatGithub([f, { ...f, ruleId: 'MCP003' }]);
    expect(out.split('\n')).toHaveLength(2);
  });
  it('normaliza backslash do file para forward slash', () => {
    const finding: Finding = { ...f, location: { ...f.location, file: 'src\\t.json' } };
    expect(formatGithub([finding])).toContain('file=src/t.json,');
  });
});
