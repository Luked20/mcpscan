import { statSync } from 'node:fs';
import { discover } from './collect/index.js';
import { runRules } from './core/engine.js';
import { RULES } from './rules/index.js';
import { atLeast } from './core/severity.js';
import type { Finding, Severity } from './core/types.js';

export const HELP_BASE_URI = 'https://github.com/luked20/mcpscan/blob/main/docs/rules/';

export interface ScanOptions {
  path: string;
  failOn: Severity | 'none';
  rules?: string[];
  disable?: string[];
}

export interface ScanResult {
  findings: Finding[];
  exitCode: 0 | 1 | 2;
  stats: { files: number; tools: number; skills: number };
  error?: string;
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const empty = { files: 0, tools: 0, skills: 0 };

  try {
    statSync(opts.path);
  } catch {
    return { findings: [], exitCode: 2, stats: empty, error: `caminho não encontrado: ${opts.path}` };
  }

  try {
    const target = await discover(opts.path);
    let active = RULES;
    if (opts.rules?.length) active = active.filter((r) => opts.rules!.includes(r.id));
    if (opts.disable?.length) active = active.filter((r) => !opts.disable!.includes(r.id));

    const findings = runRules(target, active, HELP_BASE_URI);
    const stats = {
      files: new Set(target.tools.map((t) => t.origin.file)).size,
      tools: target.tools.length,
      skills: target.skills.length,
    };
    const fails = opts.failOn !== 'none' && findings.some((f) => atLeast(f.severity, opts.failOn as Severity));
    return { findings, exitCode: fails ? 1 : 0, stats };
  } catch (err) {
    return { findings: [], exitCode: 2, stats: empty, error: (err as Error).message };
  }
}
