import { extname } from 'node:path/posix';
import type { SourceFile } from '../core/types.js';

/**
 * Extension -> language, for the extensions `discover()` actually globs
 * (`ts`, `js`, and their common alternate extensions). MCP008 only inspects
 * `ts`/`js`; `py` is here because the IR already has a slot for it (future
 * rule), not because anything globs `.py` yet.
 */
const LANGUAGE_BY_EXT: Record<string, SourceFile['language']> = {
  '.ts': 'ts', '.tsx': 'ts', '.mts': 'ts', '.cts': 'ts',
  '.js': 'js', '.jsx': 'js', '.mjs': 'js', '.cjs': 'js',
  '.py': 'py',
};

/**
 * Directory segments that mark a file as test code rather than deployed
 * code, checked against every path segment *except* the basename.
 */
const TEST_DIR_SEGMENTS = new Set(['tests', 'test', '__tests__', '__mocks__', 'spec']);

/** `foo.test.ts`, `foo.spec.js`, ... — a basename with a `.test.` / `.spec.` segment. */
const TEST_BASENAME_RE = /\.(test|spec)\.[^/.]+$/i;

/**
 * `isTestFile(file)` — true when `file` (a `/`-separated path, relative to
 * the scan root, as produced by `discover()`) is test code rather than
 * deployed code: a `tests/`, `test/`, `__tests__/`, `__mocks__/`, or `spec/`
 * path segment anywhere above the file, or a `*.test.*` / `*.spec.*`
 * basename.
 *
 * This lives in the *collector*, not in any individual rule, on purpose:
 * MCP008 flags a tool-handler sink, and a sink that only ever runs inside a
 * test file never runs in front of an agent — it is not deployed code, so
 * it is not a real finding. The same reasoning applies to every future rule
 * that inspects `SourceFile.text`, so the exclusion belongs where
 * `SourceFile`s are produced, once, rather than being re-implemented (or
 * forgotten) inside each rule that consumes them. `discover()` calls this
 * before handing a file to `collectSource` at all; a caller that invokes
 * `collectSource` directly (as the rule-level unit tests do) still sees
 * every file, which is correct for testing the collector itself.
 */
export function isTestFile(file: string): boolean {
  const segments = file.split('/');
  const base = segments[segments.length - 1] ?? '';
  if (TEST_BASENAME_RE.test(base)) return true;
  return segments.slice(0, -1).some((seg) => TEST_DIR_SEGMENTS.has(seg));
}

/**
 * `collectSource(file, text)` — same no-I/O contract as the other collectors.
 * Trivial by design: classify the language from the extension and carry the
 * text as-is. There is nothing to parse or fail on here (unlike a manifest or
 * a skill, a source file has no structure a collector could reject), so there
 * is no `unreadable` case for this collector to report.
 */
export function collectSource(file: string, text: string): SourceFile {
  const ext = extname(file).toLowerCase();
  return { file, text, language: LANGUAGE_BY_EXT[ext] ?? 'other' };
}
