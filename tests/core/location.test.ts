import { describe, it, expect } from 'vitest';
import { createLineIndex, offsetToPosition, makeLocation } from '../../src/core/location.js';

const TEXT = 'linha um\nlinha dois\n\nlinha quatro';

describe('location', () => {
  it('offset 0 é linha 1 coluna 1', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 0, TEXT.length)).toEqual({ line: 1, column: 1 });
  });
  it('primeiro char da linha 2', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 9, TEXT.length)).toEqual({ line: 2, column: 1 });
  });
  it('linha vazia', () => {
    expect(offsetToPosition(createLineIndex(TEXT), 20, TEXT.length)).toEqual({ line: 3, column: 1 });
  });
  it('último char', () => {
    const idx = createLineIndex(TEXT);
    expect(offsetToPosition(idx, TEXT.length - 1, TEXT.length)).toEqual({ line: 4, column: 12 });
  });
  it('offset negativo é preso no início do texto', () => {
    expect(offsetToPosition(createLineIndex(TEXT), -5, TEXT.length)).toEqual({ line: 1, column: 1 });
  });
  it('offset além do fim é preso no fim do texto', () => {
    // Antes: offset 999 num texto de 33 chars devolvia coluna 998 — uma coluna
    // que não existe, direto para uma anotação impossível no SARIF.
    expect(offsetToPosition(createLineIndex(TEXT), 999, TEXT.length))
      .toEqual(offsetToPosition(createLineIndex(TEXT), TEXT.length, TEXT.length));
  });
  it('offset além do fim num texto de 3 chars', () => {
    const t = 'ab\n';
    expect(offsetToPosition(createLineIndex(t), 999, t.length)).toEqual({ line: 2, column: 1 });
  });
  it('makeLocation prende o fim ao tamanho do texto', () => {
    const loc = makeLocation('a.json', TEXT, 0, 9999);
    expect(loc.endLine).toBe(4);
    expect(loc.endColumn).toBe(13);
  });
  it('makeLocation produz início e fim', () => {
    const loc = makeLocation('a/b.json', TEXT, 9, 5, 'tools[0].name');
    expect(loc).toEqual({
      file: 'a/b.json', line: 2, column: 1, endLine: 2, endColumn: 6,
      jsonPath: 'tools[0].name',
    });
  });
});
