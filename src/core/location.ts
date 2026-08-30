import type { SourceLocation } from './types.js';

/** Offsets where each line starts. Index 0 = line 1. */
export function createLineIndex(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/**
 * `textLength` is required on purpose: without it, an out-of-range offset turns
 * into a made-up position (offset -5 -> column -4; offset 999 in a 3-char text
 * -> column 998) that SARIF then annotates as if it were real.
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

/**
 * A key that can be written after a dot without becoming ambiguous: no dot of
 * its own, no bracket, no quote, and not empty.
 */
const SIMPLE_KEY_RE = /^[^.[\]"]+$/;

/**
 * Renders path segments for display: `tools[0].inputSchema.properties.path`.
 *
 * A key that would make the dotted form ambiguous is bracket-quoted instead —
 * `mcpServers["awslabs.mysql-mcp-server"].args`. That case is not theoretical:
 * PyPI-style server names contain dots, and writing one with a plain dot
 * produces a path that reads as two nested keys and points at nothing.
 *
 * This is display only. Nothing parses it back — `loc()` takes segments, so
 * the segmentation is never inferred from a string (see `ToolDefinition.loc`
 * in `types.ts`).
 */
export function formatJsonPath(segments: readonly (string | number)[]): string {
  let out = '';
  for (const segment of segments) {
    if (typeof segment === 'number') {
      out += `[${segment}]`;
    } else if (SIMPLE_KEY_RE.test(segment)) {
      out += out === '' ? segment : `.${segment}`;
    } else {
      out += `[${JSON.stringify(segment)}]`;
    }
  }
  return out;
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
