import { describe, it, expect } from 'vitest';
import { compareSeverity, atLeast, rank, isFailOn } from '../../src/core/severity.js';
import type { Severity } from '../../src/core/types.js';

describe('severity', () => {
  it('ranks critical above high', () => {
    expect(compareSeverity('critical', 'high')).toBeGreaterThan(0);
  });
  it('atLeast is inclusive at the threshold', () => {
    expect(atLeast('high', 'high')).toBe(true);
    expect(atLeast('medium', 'high')).toBe(false);
    expect(atLeast('critical', 'high')).toBe(true);
  });
  it('rank throws on an unknown severity instead of returning -1', () => {
    // -1 made atLeast(anything, 'NONE') turn true and the threshold accept everything.
    expect(() => rank('NONE' as Severity)).toThrow(/unknown/);
    expect(() => rank('none' as Severity)).toThrow();
    expect(() => atLeast('info', 'NONE' as Severity)).toThrow();
  });
  it('isFailOn accepts only the documented values', () => {
    for (const v of ['critical', 'high', 'medium', 'low', 'info', 'none']) {
      expect(isFailOn(v)).toBe(true);
    }
    for (const v of ['NONE', 'High', '', undefined, null, 1]) {
      expect(isFailOn(v)).toBe(false);
    }
  });
});
