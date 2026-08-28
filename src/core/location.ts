import type { SourceLocation } from './types.js';

/** Offsets onde cada linha começa. Índice 0 = linha 1. */
export function createLineIndex(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

export function offsetToPosition(lineStarts: number[], offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - lineStarts[lo]! + 1 };
}

export function makeLocation(
  file: string,
  text: string,
  offset: number,
  length: number,
  jsonPath?: string,
  lineStarts = createLineIndex(text),
): SourceLocation {
  const start = offsetToPosition(lineStarts, offset);
  const end = offsetToPosition(lineStarts, offset + length);
  return {
    file,
    line: start.line,
    column: start.column,
    endLine: end.line,
    endColumn: end.column,
    ...(jsonPath !== undefined ? { jsonPath } : {}),
  };
}
