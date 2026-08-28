import { describe, it, expect, vi } from 'vitest';
import type { Rule } from '../../src/core/types.js';

// Uma regra que estoura em todo subject. O scan tem que dizer "não consegui olhar"
// (exit 2), não "está limpo" (exit 0) — que era o resultado com o finding `info`.
vi.mock('../../src/rules/index.js', () => {
  const boom: Rule = {
    id: 'BOOM001', title: 'explode', severity: 'critical', confidence: 'high',
    appliesTo: 'tool',
    check: () => { throw new Error('Cannot read properties of undefined'); },
  };
  return { RULES: [boom] };
});

const { scan } = await import('../../src/scan.js');

describe('scan com regra quebrada', () => {
  it('retorna exit 2 e nomeia a regra que falhou', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'high' });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('BOOM001');
    expect(r.error).toContain('Cannot read properties of undefined');
  });

  it('exit 2 mesmo com --fail-on none', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'none' });
    expect(r.exitCode).toBe(2);
  });
});
