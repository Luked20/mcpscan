import { glob } from 'tinyglobby';
import { readFile, stat } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { collectManifest } from './mcp-manifest.js';
import type { ScanTarget, ToolDefinition } from '../core/types.js';

const IGNORE = ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**'];
const MAX_BYTES = 2_000_000;

/**
 * `root` can be a directory or a file. The CLI advertises both
 * (`[path]  directory or file to scan`); before this, a file became the glob's
 * `cwd`, matched nothing, and the scan exited clean without having read anything.
 */
export async function discover(root: string): Promise<ScanTarget> {
  const abs = resolve(root);
  const isDir = (await stat(abs)).isDirectory();

  // Relative paths are always relative to `base`, whether in the directory case
  // (base = the directory itself) or the file case (base = its parent folder,
  // so the relative path is the basename).
  const base = isDir ? abs : dirname(abs);
  const files = isDir
    ? await glob(['**/*.json'], { cwd: abs, ignore: IGNORE, dot: true, absolute: true })
    : [abs];

  const tools: ToolDefinition[] = [];
  let filesExamined = 0;

  for (const file of files) {
    const rel = relative(base, file).split('\\').join('/');
    let text: string;
    try {
      // stat before read: the cap is on bytes on disk. Reading first buffered
      // 500 MB into memory just to discard it, and `String.length` counts UTF-16
      // units, not bytes.
      const { size } = await stat(file);
      if (size > MAX_BYTES) continue;
      text = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    filesExamined += 1;
    tools.push(...collectManifest(rel, text));
  }

  return { root: base, servers: [], tools, skills: [], sourceFiles: [], filesExamined };
}
