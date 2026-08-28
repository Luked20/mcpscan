import { describe, it, expect } from 'vitest';
import type { Rule, SkillDefinition, ToolDefinition } from '../../src/core/types.js';

const loc = { file: 'a.json', line: 1, column: 1, endLine: 1, endColumn: 2 };
const meta = { id: 'X001', title: 't', severity: 'high', confidence: 'high' } as const;

/**
 * Guarda de regressão de *tipo*, não de runtime.
 *
 * Com o antigo `Rule<S>` genérico, uma regra declarando `appliesTo: 'tool'` mas
 * tipada como `Rule<SkillDefinition>` compilava sem erro (bivariância de parâmetro
 * em método). O engine passava um `ToolDefinition`, `subject.body.slice()` estourava,
 * e o throw virava um finding `info` -> exit 0 num scan completamente quebrado.
 *
 * O `@ts-expect-error` abaixo falha o build se o erro parar de acontecer.
 */
describe('Rule é uma união discriminada por appliesTo', () => {
  it('não aceita check(SkillDefinition) para appliesTo: tool', () => {
    const wrong = {
      ...meta,
      appliesTo: 'tool',
      check: (subject: SkillDefinition) => [
        { location: loc, message: subject.body, remediation: 'r' },
      ],
    } as const;

    // @ts-expect-error appliesTo 'tool' exige check(subject: ToolDefinition, ...)
    const asRule: Rule = wrong;
    expect(asRule.appliesTo).toBe('tool');
  });

  it('aceita check(ToolDefinition) para appliesTo: tool', () => {
    const right: Rule = {
      ...meta,
      appliesTo: 'tool',
      check: (subject: ToolDefinition) => [
        { location: subject.origin, message: subject.name, remediation: 'r' },
      ],
    };
    expect(right.appliesTo).toBe('tool');
  });
});
