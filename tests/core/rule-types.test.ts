import { describe, it, expect } from 'vitest';
import type { Rule, SkillDefinition, ToolDefinition } from '../../src/core/types.js';

const loc = { file: 'a.json', line: 1, column: 1, endLine: 1, endColumn: 2 };
const meta = { id: 'X001', title: 't', severity: 'high', confidence: 'high' } as const;

/**
 * A *type* regression guard, not a runtime one.
 *
 * With the old generic `Rule<S>`, a rule declaring `appliesTo: 'tool'` but typed
 * `Rule<SkillDefinition>` compiled without error (method-parameter bivariance).
 * The engine would pass a `ToolDefinition`, `subject.body.slice()` would throw,
 * and the throw turned into an `info` finding -> exit 0 on a completely broken scan.
 *
 * The `@ts-expect-error` below fails the build if the error stops happening.
 */
describe('Rule is a union discriminated by appliesTo', () => {
  it('does not accept check(SkillDefinition) for appliesTo: tool', () => {
    const wrong = {
      ...meta,
      appliesTo: 'tool',
      check: (subject: SkillDefinition) => [
        { location: loc, message: subject.body, remediation: 'r' },
      ],
    } as const;

    // @ts-expect-error appliesTo 'tool' requires check(subject: ToolDefinition, ...)
    const asRule: Rule = wrong;
    expect(asRule.appliesTo).toBe('tool');
  });

  it('accepts check(ToolDefinition) for appliesTo: tool', () => {
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
