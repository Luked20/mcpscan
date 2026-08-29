import { describe, it, expect } from 'vitest';
import { collectSource } from '../../src/collect/source.js';

describe('collectSource', () => {
  it.each([
    ['server.ts', 'ts'],
    ['server.tsx', 'ts'],
    ['server.mts', 'ts'],
    ['server.cts', 'ts'],
    ['server.js', 'js'],
    ['server.jsx', 'js'],
    ['server.mjs', 'js'],
    ['server.cjs', 'js'],
    ['server.py', 'py'],
    ['README.md', 'other'],
    ['server', 'other'],
  ] as const)('classifies %s as %s', (file, language) => {
    expect(collectSource(file, 'text').language).toBe(language);
  });

  it('carries the text through unchanged', () => {
    const text = 'export const x = 1;';
    expect(collectSource('a.ts', text).text).toBe(text);
  });

  it('carries the file path through unchanged', () => {
    expect(collectSource('src/collect/index.ts', 'x').file).toBe('src/collect/index.ts');
  });
});
