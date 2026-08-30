import { glob } from 'tinyglobby';
import { readFile, stat } from 'node:fs/promises';
import { basename, dirname, extname, relative, resolve } from 'node:path';
import { collectManifest } from './mcp-manifest.js';
import { collectMcpConfig } from './mcp-config.js';
import { collectSkill } from './skill-md.js';
import { collectSource, isTestFile } from './source.js';
import type {
  ScanTarget, ServerDefinition, SkillDefinition, SourceFile, ToolDefinition, UnreadableFile,
} from '../core/types.js';

const IGNORE = ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**'];
const MAX_BYTES = 2_000_000;

/** Basenames recognized as MCP client config files, in addition to the manifest scan. */
const CONFIG_BASENAMES = new Set(['.mcp.json', 'mcp.json', 'claude_desktop_config.json']);

/** Extensions routed to the source collector (MCP008) rather than the manifest collector. */
const SOURCE_EXTENSIONS = new Set(['.ts', '.js', '.mjs', '.cjs', '.mts', '.cts']);

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
    ? await glob(
        ['**/*.json', '**/SKILL.md', '**/*.{ts,js,mjs,cjs,mts,cts}'],
        { cwd: abs, ignore: IGNORE, dot: true, absolute: true },
      )
    : [abs];

  const tools: ToolDefinition[] = [];
  const servers: ServerDefinition[] = [];
  const skills: SkillDefinition[] = [];
  const sourceFiles: SourceFile[] = [];
  const unreadable: UnreadableFile[] = [];
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
      // The filename declared this is a skill. If it will not parse, the scanner
      // cannot vouch for it, and saying nothing would read as "scanned, clean".
      else unreadable.push({ file: rel, reason: 'SKILL.md frontmatter is missing or is not valid YAML' });
      continue;
    }

    if (SOURCE_EXTENSIONS.has(extname(file).toLowerCase())) {
      // Test code never runs in front of an agent -- a sink (or any future
      // source-rule pattern) inside it is not deployed code, so it is not a
      // finding. Skipped here, at the collector, so every source rule
      // inherits the exclusion rather than each reimplementing it. See
      // isTestFile()'s doc comment in source.ts.
      if (isTestFile(rel)) continue;
      // Source text has no structure a collector could reject -- nothing here
      // to fail closed on, so there's no unreadable case (see source.ts).
      sourceFiles.push(collectSource(rel, text));
      continue;
    }

    tools.push(...collectManifest(rel, text));
    // These files are already being read for the manifest pass above; this is
    // an additional collector pass over the same text, not a second file read.
    if (CONFIG_BASENAMES.has(basename(file))) {
      const found = collectMcpConfig(rel, text);
      if (found.length > 0) servers.push(...found);
      // Same reasoning as SKILL.md: the name declared it is an MCP client config.
      else unreadable.push({ file: rel, reason: 'no mcpServers/servers block, or the JSON is malformed' });
    }
  }

  return { root: base, servers, tools, skills, sourceFiles, unreadable, filesExamined };
}
