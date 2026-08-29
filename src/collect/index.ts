import { glob } from 'tinyglobby';
import { readFile, stat } from 'node:fs/promises';
import { basename, dirname, relative, resolve } from 'node:path';
import { collectManifest } from './mcp-manifest.js';
import { collectMcpConfig } from './mcp-config.js';
import { collectSkill } from './skill-md.js';
import type { ScanTarget, ServerDefinition, SkillDefinition, ToolDefinition } from '../core/types.js';

const IGNORE = ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**'];
const MAX_BYTES = 2_000_000;

/** Basenames recognized as MCP client config files, in addition to the manifest scan. */
const CONFIG_BASENAMES = new Set(['.mcp.json', 'mcp.json', 'claude_desktop_config.json']);

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
    ? await glob(['**/*.json', '**/SKILL.md'], { cwd: abs, ignore: IGNORE, dot: true, absolute: true })
    : [abs];

  const tools: ToolDefinition[] = [];
  const servers: ServerDefinition[] = [];
  const skills: SkillDefinition[] = [];
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

    if (basename(file) === 'SKILL.md') {
      const skill = collectSkill(rel, text);
      if (skill) skills.push(skill);
      continue;
    }

    tools.push(...collectManifest(rel, text));
    // These files are already being read for the manifest pass above; this is
    // an additional collector pass over the same text, not a second file read.
    if (CONFIG_BASENAMES.has(basename(file))) {
      servers.push(...collectMcpConfig(rel, text));
    }
  }

  return { root: base, servers, tools, skills, sourceFiles: [], filesExamined };
}
