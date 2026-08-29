import type { Severity } from './types.js';

export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

/** Values accepted by `--fail-on`. */
export const FAIL_ON_VALUES = [...SEVERITY_ORDER, 'none'] as const;
export type FailOn = (typeof FAIL_ON_VALUES)[number];

export function isFailOn(v: unknown): v is FailOn {
  return typeof v === 'string' && (FAIL_ON_VALUES as readonly string[]).includes(v);
}

/**
 * `indexOf` used to return -1 for an unknown value and `atLeast` would then accept
 * any severity — `--fail-on NONE` (uppercase) silently disabled the threshold.
 * Better to throw: the scan converts the exception into exit 2.
 */
export function rank(s: Severity): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s);
  if (i < 0) throw new Error(`unknown severity: ${String(s)}`);
  return i;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return rank(a) - rank(b);
}

export function atLeast(s: Severity, threshold: Severity): boolean {
  return rank(s) >= rank(threshold);
}
