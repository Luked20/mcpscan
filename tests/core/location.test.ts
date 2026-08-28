import { describe, it, expect } from 'vitest';
import { createLineIndex, offsetToPosition, makeLocation } from '../../src/core/location.js';

const TEXT = 'linha um\nlinha dois\n\nlinha quatro';

describe('location', () => {
  it('offset 0 é linha 1 coluna 1', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 0)).toEqual({ line: 1, column: 1 });
  });
  it('primeiro char da linha 2', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 9)).toEqual({ line: 2, column: 1 });
  });
  it('linha vazia', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 20)).toEqual({ line: 3, column: 1 });
  });
  it('último char', () => {
    const idx = createLineIndex(TEXT);
    expect(offsetToPosition(idx, TEXT.length - 1)).toEqual({ line: 4, column: 12 });
  });
  it('makeLocation produz início e fim', () => {
    const loc = makeLocation('a/b.json', TEXT, 9, 5, 'tools[0].name');
    expect(loc).toEqual({
      file: 'a/b.json', line: 2, column: 1, endLine: 2, endColumn: 6,
      jsonPath: 'tools[0].name',
    });
  });
});
