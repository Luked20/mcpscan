import { describe, it, expect } from 'vitest';
import { SEVERITY_ORDER } from '../../src/core/severity.js';
import { CONFIDENCE_CEILING } from '../../src/core/types.js';

describe('IR contracts', () => {
  it('every confidence level has a valid severity ceiling', () => {
    for (const [conf, ceiling] of Object.entries(CONFIDENCE_CEILING)) {
      expect(SEVERITY_ORDER).toContain(ceiling);
      expect(['high', 'medium', 'low']).toContain(conf);
    }
  });
  it('low confidence never allows critical', () => {
    expect(CONFIDENCE_CEILING.low).toBe('medium');
    expect(CONFIDENCE_CEILING.medium).toBe('high');
    expect(CONFIDENCE_CEILING.high).toBe('critical');
  });
});
