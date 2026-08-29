import { describe, it, expect } from 'vitest';
import { formatSarif } from '../../src/report/sarif.js';
import { RULES } from '../../src/rules/index.js';
import type { Finding } from '../../src/core/types.js';

const base: Finding = {
  ruleId: 'MCP002', title: 'Unicode invisível', severity: 'critical', confidence: 'high',
  location: { file: 'src/tools.json', line: 14, column: 32, endLine: 14, endColumn: 40, jsonPath: 'tools[1].description' },
  message: 'msg', remediation: 'fix', evidence: 'abc',
  helpUri: 'https://x/MCP002.md', provenance: 'static',
};

describe('formatSarif', () => {
  const doc = JSON.parse(formatSarif([base], RULES, '0.1.0'));
  it('tem versão 2.1.0 e schema', () => {
    expect(doc.version).toBe('2.1.0');
    expect(doc.$schema).toContain('sarif');
  });
  it('declara todas as regras do registry no driver', () => {
    expect(doc.runs[0].tool.driver.rules).toHaveLength(RULES.length);
  });
  it('mapeia critical para level error', () => {
    expect(doc.runs[0].results[0].level).toBe('error');
  });
  it('emite região com linha e coluna', () => {
    expect(doc.runs[0].results[0].locations[0].physicalLocation.region)
      .toEqual({ startLine: 14, startColumn: 32, endLine: 14, endColumn: 40 });
  });
  it('fingerprint NÃO muda quando a linha muda', () => {
    const moved = { ...base, location: { ...base.location, line: 99, endLine: 99 } };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([moved], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).toBe(b['mcpScan/v1']);
  });
  it('fingerprint muda quando o jsonPath muda', () => {
    const other = { ...base, location: { ...base.location, jsonPath: 'tools[2].description' } };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([other], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).not.toBe(b['mcpScan/v1']);
  });
  it('fingerprint muda quando o ruleId muda', () => {
    const other: Finding = { ...base, ruleId: 'MCP099' };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([other], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).not.toBe(b['mcpScan/v1']);
  });
  it('fingerprint muda quando o file muda', () => {
    const other = { ...base, location: { ...base.location, file: 'src/other.json' } };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([other], RULES, '0.1.0')).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).not.toBe(b['mcpScan/v1']);
  });
  it('artifactLocation.uri usa forward slashes mesmo com backslash no file', () => {
    const winPath = { ...base, location: { ...base.location, file: 'src\\tools.json' } };
    const d = JSON.parse(formatSarif([winPath], RULES, '0.1.0'));
    expect(d.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/tools.json');
  });
  it('finding sem jsonPath e sem evidence ainda produz fingerprint estável e saída válida', () => {
    const minimal: Finding = {
      ruleId: 'MCP002', title: 'x', severity: 'low', confidence: 'low',
      location: { file: 'a.json', line: 1, column: 1, endLine: 1, endColumn: 2 },
      message: 'm', remediation: 'r', helpUri: 'https://x', provenance: 'static',
    };
    const d1 = JSON.parse(formatSarif([minimal], RULES, '0.1.0'));
    const d2 = JSON.parse(formatSarif([minimal], RULES, '0.1.0'));
    expect(d1.runs[0].results[0].partialFingerprints['mcpScan/v1'])
      .toBe(d2.runs[0].results[0].partialFingerprints['mcpScan/v1']);
    expect(typeof d1.runs[0].results[0].partialFingerprints['mcpScan/v1']).toBe('string');
  });
  it('zero findings produz documento válido com results vazio e regras completas declaradas', () => {
    const d = JSON.parse(formatSarif([], RULES, '0.1.0'));
    expect(d.runs[0].results).toEqual([]);
    expect(d.runs[0].tool.driver.rules).toHaveLength(RULES.length);
  });
  it('todo result.ruleId corresponde a uma regra declarada no driver', () => {
    const d = JSON.parse(formatSarif([base], RULES, '0.1.0'));
    const declared = new Set(d.runs[0].tool.driver.rules.map((r: { id: string }) => r.id));
    for (const r of d.runs[0].results) {
      expect(declared.has(r.ruleId)).toBe(true);
    }
  });
  it('message.text não é vazio e contém mensagem e remediação', () => {
    const text = doc.runs[0].results[0].message.text as string;
    expect(text.length).toBeGreaterThan(0);
    expect(text).toContain('msg');
    expect(text).toContain('fix');
  });
});
