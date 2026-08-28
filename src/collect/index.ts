import { glob } from 'tinyglobby';
import { readFile, stat } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { collectManifest } from './mcp-manifest.js';
import type { ScanTarget, ToolDefinition } from '../core/types.js';

const IGNORE = ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**'];
const MAX_BYTES = 2_000_000;

/**
 * `root` pode ser um diretório ou um arquivo. O CLI anuncia os dois
 * (`[path]  diretório ou arquivo para analisar`); antes, um arquivo virava `cwd`
 * do glob, não casava com nada, e o scan saía verde sem ter lido nada.
 */
export async function discover(root: string): Promise<ScanTarget> {
  const abs = resolve(root);
  const isDir = (await stat(abs)).isDirectory();

  // Caminhos relativos são sempre relativos a `base`, tanto no caso diretório
  // (base = o próprio diretório) quanto no caso arquivo (base = a pasta dele,
  // então o relativo é o basename).
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
      // stat antes de ler: o cap é sobre bytes em disco. Ler primeiro bufferizava
      // 500 MB na memória só para descartar, e `String.length` conta unidades
      // UTF-16, não bytes.
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
