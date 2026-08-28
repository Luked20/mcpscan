import { describe, it, expect } from 'vitest';
import { compareSeverity, atLeast } from '../../src/core/severity.js';

describe('severity', () => {
  it('ordena critical acima de high', () => {
    expect(compareSeverity('critical', 'high')).toBeGreaterThan(0);
  });
  it('atLeast é inclusivo no limiar', () => {
    expect(atLeast('high', 'high')).toBe(true);
    expect(atLeast('medium', 'high')).toBe(false);
    expect(atLeast('critical', 'high')).toBe(true);
  });
});
