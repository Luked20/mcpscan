import { describe, it, expect } from 'vitest';
import { validateFormat, isFormat } from '../../src/report/format.js';

describe('--format', () => {
  it('aceita os formatos implementados', () => {
    expect(validateFormat('pretty')).toBeNull();
    expect(validateFormat('json')).toBeNull();
  });
  it('rejeita valor desconhecido e lista os válidos', () => {
    const err = validateFormat('jsonn');
    expect(err).toContain('jsonn');
    expect(err).toContain('pretty | json');
  });
  it('rejeita formato anunciado mas não implementado, em vez de emitir JSON', () => {
    expect(validateFormat('sarif')).toContain('ainda não está implementado');
    expect(validateFormat('github')).toContain('ainda não está implementado');
  });
  it('rejeita undefined', () => {
    expect(isFormat(undefined)).toBe(false);
    expect(validateFormat(undefined)).toBeTruthy();
  });
});
