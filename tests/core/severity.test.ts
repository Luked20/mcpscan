import { describe, it, expect } from 'vitest';
import { compareSeverity, atLeast, rank, isFailOn } from '../../src/core/severity.js';
import type { Severity } from '../../src/core/types.js';

describe('severity', () => {
  it('ordena critical acima de high', () => {
    expect(compareSeverity('critical', 'high')).toBeGreaterThan(0);
  });
  it('atLeast é inclusivo no limiar', () => {
    expect(atLeast('high', 'high')).toBe(true);
    expect(atLeast('medium', 'high')).toBe(false);
    expect(atLeast('critical', 'high')).toBe(true);
  });
  it('rank estoura em severidade desconhecida em vez de devolver -1', () => {
    // -1 fazia atLeast(qualquer, 'NONE') virar true e o limiar aceitar tudo.
    expect(() => rank('NONE' as Severity)).toThrow(/desconhecida/);
    expect(() => rank('none' as Severity)).toThrow();
    expect(() => atLeast('info', 'NONE' as Severity)).toThrow();
  });
  it('isFailOn aceita só os valores documentados', () => {
    for (const v of ['critical', 'high', 'medium', 'low', 'info', 'none']) {
      expect(isFailOn(v)).toBe(true);
    }
    for (const v of ['NONE', 'High', '', undefined, null, 1]) {
      expect(isFailOn(v)).toBe(false);
    }
  });
});
