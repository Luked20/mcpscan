import type { SourceLocation } from './types.js';

/** Offsets onde cada linha começa. Índice 0 = linha 1. */
export function createLineIndex(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/**
 * `textLength` é obrigatório de propósito: sem ele um offset fora do texto vira
 * uma posição inventada (offset -5 -> coluna -4; offset 999 num texto de 3 chars
 * -> coluna 998) que o SARIF anota como se fosse real.
 */
export function offsetToPosition(
  lineStarts: number[],
  offset: number,
  textLength: number,
): { line: number; column: number } {
  const clamped = offset < 0 ? 0 : offset > textLength ? textLength : offset;
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= clamped) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: clamped - lineStarts[lo]! + 1 };
}

export function makeLocation(
  file: string,
  text: string,
  offset: number,
  length: number,
  jsonPath?: string,
  lineStarts = createLineIndex(text),
): SourceLocation {
  const start = offsetToPosition(lineStarts, offset, text.length);
  const end = offsetToPosition(lineStarts, offset + length, text.length);
  return {
    file,
    line: start.line,
    column: start.column,
    endLine: end.line,
    endColumn: end.column,
    ...(jsonPath !== undefined ? { jsonPath } : {}),
  };
}
