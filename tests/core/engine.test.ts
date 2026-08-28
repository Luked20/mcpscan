import { describe, it, expect } from 'vitest';
import { runRules } from '../../src/core/engine.js';
import { RULES } from '../../src/rules/index.js';
import type { Rule, ScanTarget, SourceLocation, ToolDefinition } from '../../src/core/types.js';

const loc = { file: 'a.json', line: 1, column: 1, endLine: 1, endColumn: 2 };
const at = (file: string, line: number, column: number): SourceLocation =>
  ({ file, line, column, endLine: line, endColumn: column + 1 });
const tool = (name: string): ToolDefinition => ({ name, origin: loc, loc: () => loc });
const target = (tools: ToolDefinition[]): ScanTarget =>
  ({ root: '.', servers: [], tools, skills: [], sourceFiles: [], filesExamined: 1 });

const noisy: Rule = {
  id: 'TEST001', title: 'ruidosa', severity: 'critical', confidence: 'low',
  appliesTo: 'tool',
  check: () => [{ location: loc, message: 'm', remediation: 'r' }],
};

/** Emite um finding numa localização fixa, para exercitar os desempates da ordenação. */
const atRule = (id: string, location: SourceLocation): Rule => ({
  id, title: 'fixa', severity: 'high', confidence: 'high', appliesTo: 'tool',
  check: () => [{ location, message: 'm', remediation: 'r' }],
});

describe('engine', () => {
  it('preenche metadados da regra no finding', () => {
    const [f] = runRules(target([tool('a')]), [noisy], 'https://x/').findings;
    expect(f!.ruleId).toBe('TEST001');
    expect(f!.helpUri).toBe('https://x/TEST001.md');
    expect(f!.provenance).toBe('static');
  });

  it('aplica o teto de confiança: low nunca vira critical', () => {
    const [f] = runRules(target([tool('a')]), [noisy], 'https://x/').findings;
    expect(f!.severity).toBe('medium');
  });

  it('ordena por severidade decrescente', () => {
    const low: Rule = { ...noisy, id: 'TEST002', severity: 'low', confidence: 'high' };
    const out = runRules(target([tool('a')]), [low, noisy], 'https://x/').findings;
    expect(out.map((f) => f.ruleId)).toEqual(['TEST001', 'TEST002']);
  });

  it('desempata por arquivo, depois linha, depois coluna, depois ruleId', () => {
    // Os ids estão deliberadamente fora da ordem esperada: se qualquer desempate
    // sumir, o resultado cai na ordem alfabética de ruleId e o teste falha.
    const rules: Rule[] = [
      atRule('D', at('a.json', 1, 1)),
      atRule('C', at('a.json', 1, 5)),
      atRule('B', at('a.json', 2, 1)),
      atRule('A', at('b.json', 1, 1)),
      atRule('Z', at('a.json', 1, 1)),
    ];
    const out = runRules(target([tool('a')]), rules, 'https://x/').findings;
    expect(out.map((f) => f.ruleId)).toEqual(['D', 'Z', 'C', 'B', 'A']);
  });

  it('ordena linha numericamente, não lexicograficamente', () => {
    const out = runRules(target([tool('a')]), [
      atRule('R1', at('a.json', 10, 1)),
      atRule('R2', at('a.json', 9, 1)),
    ], 'https://x/').findings;
    expect(out.map((f) => f.location.line)).toEqual([9, 10]);
  });

  it('ordena arquivos por codepoint, não pelo ICU do host', () => {
    // localeCompare em en-US coloca 'a.json' antes de 'A.json'; a ordem por
    // codepoint é a única estável entre máquinas.
    const out = runRules(target([tool('a')]), [
      atRule('R1', at('a.json', 1, 1)),
      atRule('R2', at('A.json', 1, 1)),
    ], 'https://x/').findings;
    expect(out.map((f) => f.location.file)).toEqual(['A.json', 'a.json']);
  });
});

describe('engine: regra que lança', () => {
  const boom: Rule = {
    id: 'BOOM001', title: 'explode', severity: 'high', confidence: 'high', appliesTo: 'tool',
    check: () => { throw new Error('Cannot read properties of undefined'); },
  };

  it('reporta a falha em failures, não como finding info', () => {
    const r = runRules(target([tool('a'), tool('b'), tool('c')]), [boom], 'https://x/');
    expect(r.findings).toEqual([]);
    expect(r.failures).toEqual([
      { ruleId: 'BOOM001', message: 'Cannot read properties of undefined', subjectCount: 3 },
    ]);
  });

  it('não emite uma entrada por subject', () => {
    const r = runRules(target([tool('a'), tool('b'), tool('c')]), [boom], 'https://x/');
    expect(r.failures).toHaveLength(1);
  });

  it('não silencia as outras regras', () => {
    const r = runRules(target([tool('a')]), [boom, noisy], 'https://x/');
    expect(r.findings.map((f) => f.ruleId)).toEqual(['TEST001']);
    expect(r.failures.map((f) => f.ruleId)).toEqual(['BOOM001']);
  });

  it('não inventa localização de um server não relacionado', () => {
    const r = runRules(target([tool('a')]), [boom], 'https://x/');
    expect(r.findings.some((f) => f.ruleId === 'ENGINE001')).toBe(false);
  });
});

describe('registry', () => {
  it('não tem IDs duplicados', () => {
    const ids = RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
  it('toda regra tem título e appliesTo', () => {
    for (const r of RULES) {
      expect(r.title.length).toBeGreaterThan(0);
      expect(['tool', 'server', 'skill', 'sourceFile', 'target']).toContain(r.appliesTo);
    }
  });
});
