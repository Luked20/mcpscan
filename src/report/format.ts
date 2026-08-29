/** Output formats actually implemented. */
export const FORMATS = ['pretty', 'json', 'sarif', 'github'] as const;
export type Format = (typeof FORMATS)[number];

/** Announced in the SPEC, not yet implemented — rejecting is more honest than emitting JSON. */
export const PLANNED_FORMATS = [] as const;

export function isFormat(v: unknown): v is Format {
  return typeof v === 'string' && (FORMATS as readonly string[]).includes(v);
}

/** `null` when the value is valid; otherwise the error message for exit 2. */
export function validateFormat(v: unknown): string | null {
  if (isFormat(v)) return null;
  const planned = (PLANNED_FORMATS as readonly string[]).includes(String(v))
    ? ` (${String(v)} is not implemented yet)`
    : '';
  return `invalid --format: ${String(v)}. Use: ${FORMATS.join(' | ')}${planned}`;
}
