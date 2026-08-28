import { glob } from 'tinyglobby';
import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { collectManifest } from './mcp-manifest.js';
import type { ScanTarget, ToolDefinition } from '../core/types.js';

const IGNORE = ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**'];
const MAX_BYTES = 2_000_000;

export async function discover(root: string): Promise<ScanTarget> {
  const abs = resolve(root);
  const files = await glob(['**/*.json'], { cwd: abs, ignore: IGNORE, dot: true, absolute: true });

  const tools: ToolDefinition[] = [];
  for (const file of files) {
    const rel = relative(abs, file).split('\\').join('/');
    let text: string;
    try {
      text = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    if (text.length > MAX_BYTES) continue;
    tools.push(...collectManifest(rel, text));
  }

  return { root: abs, servers: [], tools, skills: [], sourceFiles: [] };
}
