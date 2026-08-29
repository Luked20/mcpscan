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
  id: 'TEST001', title: 'noisy', severity: 'critical', confidence: 'low',
  appliesTo: 'tool',
  check: () => [{ location: loc, message: 'm', remediation: 'r' }],
};

/** Emits a finding at a fixed location, to exercise the ordering tie-breakers. */
const atRule = (id: string, location: SourceLocation): Rule => ({
  id, title: 'fixed', severity: 'high', confidence: 'high', appliesTo: 'tool',
  check: () => [{ location, message: 'm', remediation: 'r' }],
});

describe('engine', () => {
  it('fills in the rule metadata on the finding', () => {
    const [f] = runRules(target([tool('a')]), [noisy], 'https://x/').findings;
    expect(f!.ruleId).toBe('TEST001');
    expect(f!.helpUri).toBe('https://x/TEST001.md');
    expect(f!.provenance).toBe('static');
  });

  it('applies the confidence ceiling: low never becomes critical', () => {
    const [f] = runRules(target([tool('a')]), [noisy], 'https://x/').findings;
    expect(f!.severity).toBe('medium');
  });

  it('sorts by descending severity', () => {
    const low: Rule = { ...noisy, id: 'TEST002', severity: 'low', confidence: 'high' };
    const out = runRules(target([tool('a')]), [low, noisy], 'https://x/').findings;
    expect(out.map((f) => f.ruleId)).toEqual(['TEST001', 'TEST002']);
  });

  it('breaks ties by file, then line, then column, then ruleId', () => {
    // The ids are deliberately out of the expected order: if any tie-breaker
    // disappears, the result falls back to alphabetical ruleId order and the test fails.
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

  it('sorts line numerically, not lexicographically', () => {
    const out = runRules(target([tool('a')]), [
      atRule('R1', at('a.json', 10, 1)),
      atRule('R2', at('a.json', 9, 1)),
    ], 'https://x/').findings;
    expect(out.map((f) => f.location.line)).toEqual([9, 10]);
  });

  it('sorts files by codepoint, not by the host ICU', () => {
    // localeCompare in en-US puts 'a.json' before 'A.json'; codepoint order
    // is the only one stable across machines.
    const out = runRules(target([tool('a')]), [
      atRule('R1', at('a.json', 1, 1)),
      atRule('R2', at('A.json', 1, 1)),
    ], 'https://x/').findings;
    expect(out.map((f) => f.location.file)).toEqual(['A.json', 'a.json']);
  });
});

describe('engine: a rule that throws', () => {
  const boom: Rule = {
    id: 'BOOM001', title: 'explodes', severity: 'high', confidence: 'high', appliesTo: 'tool',
    check: () => { throw new Error('Cannot read properties of undefined'); },
  };

  it('reports the failure in failures, not as an info finding', () => {
    const r = runRules(target([tool('a'), tool('b'), tool('c')]), [boom], 'https://x/');
    expect(r.findings).toEqual([]);
    expect(r.failures).toEqual([
      { ruleId: 'BOOM001', message: 'Cannot read properties of undefined', subjectCount: 3 },
    ]);
  });

  it('does not emit one entry per subject', () => {
    const r = runRules(target([tool('a'), tool('b'), tool('c')]), [boom], 'https://x/');
    expect(r.failures).toHaveLength(1);
  });

  it('does not silence the other rules', () => {
    const r = runRules(target([tool('a')]), [boom, noisy], 'https://x/');
    expect(r.findings.map((f) => f.ruleId)).toEqual(['TEST001']);
    expect(r.failures.map((f) => f.ruleId)).toEqual(['BOOM001']);
  });

  it('does not invent a location for an unrelated server', () => {
    const r = runRules(target([tool('a')]), [boom], 'https://x/');
    expect(r.findings.some((f) => f.ruleId === 'ENGINE001')).toBe(false);
  });
});

describe('registry', () => {
  it('has no duplicate IDs', () => {
    const ids = RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
  it('every rule has a title and appliesTo', () => {
    for (const r of RULES) {
      expect(r.title.length).toBeGreaterThan(0);
      expect(['tool', 'server', 'skill', 'sourceFile', 'target']).toContain(r.appliesTo);
    }
  });
});
