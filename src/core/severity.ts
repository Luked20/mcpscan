import type { Severity } from './types.js';

export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

/** Valores aceitos por `--fail-on`. */
export const FAIL_ON_VALUES = [...SEVERITY_ORDER, 'none'] as const;
export type FailOn = (typeof FAIL_ON_VALUES)[number];

export function isFailOn(v: unknown): v is FailOn {
  return typeof v === 'string' && (FAIL_ON_VALUES as readonly string[]).includes(v);
}

/**
 * `indexOf` devolvia -1 para valor desconhecido e `atLeast` passava a aceitar
 * qualquer severidade — `--fail-on NONE` (maiúsculo) desligava o limiar em silêncio.
 * Melhor estourar: o scan converte a exceção em exit 2.
 */
export function rank(s: Severity): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s);
  if (i < 0) throw new Error(`severidade desconhecida: ${String(s)}`);
  return i;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return rank(a) - rank(b);
}

export function atLeast(s: Severity, threshold: Severity): boolean {
  return rank(s) >= rank(threshold);
}
