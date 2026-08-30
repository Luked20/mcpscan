/**
 * Output formats actually implemented.
 *
 * `baseline` is here rather than behind a `--write-baseline` flag of its own: a
 * baseline is a rendering of the findings, which is exactly what a format is,
 * and `--format baseline --output mcpscan-baseline.json` reuses the `--output`
 * plumbing and the validation that already exists. A `--baseline` you can
 * consume but not produce would not be a feature.
 */
export const FORMATS = ['pretty', 'json', 'sarif', 'github', 'baseline'] as const;
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
