import { describe, it, expect } from 'vitest';
import { runRules } from '../../src/core/engine.js';
import { RULES } from '../../src/rules/index.js';
import type { Rule, ScanTarget, ToolDefinition } from '../../src/core/types.js';

const loc = { file: 'a.json', line: 1, column: 1, endLine: 1, endColumn: 2 };
const tool = (name: string): ToolDefinition => ({ name, origin: loc, loc: () => loc });
const target = (tools: ToolDefinition[]): ScanTarget =>
  ({ root: '.', servers: [], tools, skills: [], sourceFiles: [] });

const noisy: Rule<ToolDefinition> = {
  id: 'TEST001', title: 'ruidosa', severity: 'critical', confidence: 'low',
  appliesTo: 'tool',
  check: () => [{ location: loc, message: 'm', remediation: 'r' }],
};

describe('engine', () => {
  it('preenche metadados da regra no finding', () => {
    const [f] = runRules(target([tool('a')]), [noisy as Rule<never>], 'https://x/');
    expect(f!.ruleId).toBe('TEST001');
    expect(f!.helpUri).toBe('https://x/TEST001.md');
    expect(f!.provenance).toBe('static');
  });
  it('aplica o teto de confiança: low nunca vira critical', () => {
    const [f] = runRules(target([tool('a')]), [noisy as Rule<never>], 'https://x/');
    expect(f!.severity).toBe('medium');
  });
  it('ordena por severidade decrescente e depois por arquivo/linha', () => {
    const low: Rule<ToolDefinition> = { ...noisy, id: 'TEST002', severity: 'low', confidence: 'high' };
    const out = runRules(target([tool('a')]), [low as Rule<never>, noisy as Rule<never>], 'https://x/');
    expect(out.map((f) => f.ruleId)).toEqual(['TEST001', 'TEST002']);
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
