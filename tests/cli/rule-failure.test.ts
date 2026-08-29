import { describe, it, expect, vi } from 'vitest';
import type { Rule } from '../../src/core/types.js';

// A rule that throws on every subject. The scan has to say "couldn't look"
// (exit 2), not "is clean" (exit 0) — which was the result with the `info` finding.
vi.mock('../../src/rules/index.js', () => {
  const boom: Rule = {
    id: 'BOOM001', title: 'explodes', severity: 'critical', confidence: 'high',
    appliesTo: 'tool',
    check: () => { throw new Error('Cannot read properties of undefined'); },
  };
  return { RULES: [boom] };
});

const { scan } = await import('../../src/scan.js');

describe('scan with a broken rule', () => {
  it('returns exit 2 and names the rule that failed', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'high' });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('BOOM001');
    expect(r.error).toContain('Cannot read properties of undefined');
  });

  it('exit 2 even with --fail-on none', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'none' });
    expect(r.exitCode).toBe(2);
  });
});
