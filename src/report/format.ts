/** Formatos de saída realmente implementados. */
export const FORMATS = ['pretty', 'json'] as const;
export type Format = (typeof FORMATS)[number];

/** Anunciados no SPEC, ainda não implementados — rejeitar é mais honesto que emitir JSON. */
export const PLANNED_FORMATS = ['sarif', 'github'] as const;

export function isFormat(v: unknown): v is Format {
  return typeof v === 'string' && (FORMATS as readonly string[]).includes(v);
}

/** `null` quando o valor é válido; senão a mensagem de erro para o exit 2. */
export function validateFormat(v: unknown): string | null {
  if (isFormat(v)) return null;
  const planned = (PLANNED_FORMATS as readonly string[]).includes(String(v))
    ? ` (${String(v)} ainda não está implementado)`
    : '';
  return `--format inválido: ${String(v)}. Use: ${FORMATS.join(' | ')}${planned}`;
}
