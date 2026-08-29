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
