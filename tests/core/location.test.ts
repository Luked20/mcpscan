import { describe, it, expect } from 'vitest';
import { createLineIndex, offsetToPosition, makeLocation } from '../../src/core/location.js';

const TEXT = 'linha um\nlinha dois\n\nlinha quatro';

describe('location', () => {
  it('offset 0 is line 1 column 1', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 0, TEXT.length)).toEqual({ line: 1, column: 1 });
  });
  it('first char of line 2', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 9, TEXT.length)).toEqual({ line: 2, column: 1 });
  });
  it('empty line', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 20, TEXT.length)).toEqual({ line: 3, column: 1 });
  });
  it('last char', () => {
    const idx = createLineIndex(TEXT);
    expect(offsetToPosition(idx, TEXT.length - 1, TEXT.length)).toEqual({ line: 4, column: 12 });
  });
  it('negative offset is clamped to the start of the text', () => {
    expect(offsetToPosition(createLineIndex(TEXT), -5, TEXT.length)).toEqual({ line: 1, column: 1 });
  });
  it('offset past the end is clamped to the end of the text', () => {
    // Before: offset 999 in a 33-char text returned column 998 — a column that
    // doesn't exist, straight into an impossible SARIF annotation.
    expect(offsetToPosition(createLineIndex(TEXT), 999, TEXT.length))
      .toEqual(offsetToPosition(createLineIndex(TEXT), TEXT.length, TEXT.length));
  });
  it('offset past the end in a 3-char text', () => {
    const t = 'ab\n';
    expect(offsetToPosition(createLineIndex(t), 999, t.length)).toEqual({ line: 2, column: 1 });
  });
  it('makeLocation clamps the end to the length of the text', () => {
    const loc = makeLocation('a.json', TEXT, 0, 9999);
    expect(loc.endLine).toBe(4);
    expect(loc.endColumn).toBe(13);
  });
  it('makeLocation produces start and end', () => {
    const loc = makeLocation('a/b.json', TEXT, 9, 5, 'tools[0].name');
    expect(loc).toEqual({
      file: 'a/b.json', line: 2, column: 1, endLine: 2, endColumn: 6,
      jsonPath: 'tools[0].name',
    });
  });
});
