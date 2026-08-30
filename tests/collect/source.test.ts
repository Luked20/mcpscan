import { describe, it, expect } from 'vitest';
import { collectSource, isTestFile } from '../../src/collect/source.js';

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

describe('isTestFile', () => {
  it.each([
    'src/handler.test.ts',
    'src/handler.spec.js',
    'tests/handler.ts',
    'test/handler.ts',
    '__tests__/handler.ts',
    '__mocks__/handler.ts',
    'spec/handler.ts',
    'src/tests/handler.ts',
    'a/b/__tests__/c/handler.ts',
  ])('flags %s as a test file', (file) => {
    expect(isTestFile(file)).toBe(true);
  });

  it.each([
    'src/handler.ts',
    'src/collect/index.ts',
    'server.ts',
    'src/latest.ts', // contains "test" as a substring, not a path segment or basename marker
    'src/protest.ts',
    'src/testing/handler.ts', // "testing" is not "test" -- the segment must match exactly
  ])('does NOT flag %s as a test file', (file) => {
    expect(isTestFile(file)).toBe(false);
  });
});
