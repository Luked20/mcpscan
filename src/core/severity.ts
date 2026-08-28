import type { Severity } from './types.js';

export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

export function rank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function compareSeverity(a: Severity, b: Severity): number {
  return rank(a) - rank(b);
}

export function atLeast(s: Severity, threshold: Severity): boolean {
  return rank(s) >= rank(threshold);
}
