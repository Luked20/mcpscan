import { describe, it, expect } from 'vitest';
import { validateFormat, isFormat } from '../../src/report/format.js';

describe('--format', () => {
  it('accepts the implemented formats', () => {
    expect(validateFormat('pretty')).toBeNull();
    expect(validateFormat('json')).toBeNull();
    expect(validateFormat('sarif')).toBeNull();
    expect(validateFormat('github')).toBeNull();
  });
  it('rejects an unknown value and lists the valid ones', () => {
    const err = validateFormat('jsonn');
    expect(err).toContain('jsonn');
    expect(err).toContain('pretty | json | sarif | github');
  });
  it('rejects undefined', () => {
    expect(isFormat(undefined)).toBe(false);
    expect(validateFormat(undefined)).toBeTruthy();
  });
});
